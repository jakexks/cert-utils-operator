package route

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"sort"
	"time"

	"github.com/go-logr/logr"
	cmutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	cmutilpki "github.com/jetstack/cert-manager/pkg/util/pki"
	routev1 "github.com/openshift/api/route/v1"
	outils "github.com/redhat-cop/operator-utils/pkg/util"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

type CertificateRequestReconciler struct {
	outils.ReconcilerBase
	Log            logr.Logger
	controllerName string
}

func (c *CertificateRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	c.controllerName = "route_certificaterequest_controller"

	isCertManagerRoute := predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			route, ok := e.Object.DeepCopyObject().(*routev1.Route)
			if !ok {
				return false
			}
			return hasCertManagerAnnotations(route)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			route, ok := e.Object.DeepCopyObject().(*routev1.Route)
			if !ok {
				return false
			}
			return hasCertManagerAnnotations(route)
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			newRoute, ok := e.ObjectNew.DeepCopyObject().(*routev1.Route)
			if !ok {
				return false
			}
			return hasCertManagerAnnotations(newRoute)
		},
		GenericFunc: func(e event.GenericEvent) bool {
			return false
		},
	}

	hasCRStatusChanged := predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			_, ok := e.Object.(*cmapi.CertificateRequest)
			return ok
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			crOld, ok := e.ObjectOld.(*cmapi.CertificateRequest)
			if !ok {
				return false
			}
			crNew, ok := e.ObjectNew.(*cmapi.CertificateRequest)
			if !ok {
				return false
			}
			oldConditions := make(map[cmapi.CertificateRequestConditionType]cmapi.CertificateRequestCondition)
			for _, oldCon := range crOld.Status.Conditions {
				oldConditions[oldCon.Type] = oldCon
			}
			for _, newCon := range crNew.Status.Conditions {
				oldCon, found := oldConditions[newCon.Type]
				if !found {
					return true
				}
				if oldCon.Status != newCon.Status {
					return true
				}
			}
			return !bytes.Equal(crOld.Status.Certificate, crNew.Status.Certificate)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			_, ok := e.Object.(*cmapi.CertificateRequest)
			return ok
		},
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&routev1.Route{
			TypeMeta: metav1.TypeMeta{Kind: "Route"},
		}, builder.WithPredicates(isCertManagerRoute)).
		// We will create cert-manager CertificateRequests to populate TLS routes, so
		// we need to respond to the creation / update events them too.
		Watches(&source.Kind{
			Type: &cmapi.CertificateRequest{
				TypeMeta: metav1.TypeMeta{Kind: "CertificateRequest"},
			},
		}, &handler.EnqueueRequestForOwner{
			OwnerType: &routev1.Route{},
		}, builder.WithPredicates(hasCRStatusChanged)).
		Complete(c)
}

func (c *CertificateRequestReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	// Fetch the Route being reconciled
	var instance *routev1.Route
	err := c.GetClient().Get(ctx, req.NamespacedName, instance)
	if err != nil {
		return c.ManageError(ctx, instance, err)
	}
	log := c.Log.WithValues("route", req.NamespacedName)

	// The isCertManagerRoute predicate means we should only receive routes we care about.
	// but the TLS block could be missing / unset so set a default.
	if instance.Spec.TLS == nil {
		instance.Spec.TLS = &routev1.TLSConfig{
			Termination: routev1.TLSTerminationEdge,
		}
	}

	// Check if the certificate is up-to-date and not expired.
	upToDate, renewalTime := func(route *routev1.Route) (bool, time.Time) {
		pk, err := cmutilpki.DecodePrivateKeyBytes([]byte(route.Spec.TLS.Key))
		if err != nil {
			log.V(5).Info("Route has missing or invalid private key", "err", err)
			return false, time.Time{}
		}
		certs, err := cmutilpki.DecodeX509CertificateChainBytes([]byte(route.Spec.TLS.Certificate))
		if err != nil {
			log.V(5).Info("Route has missing or invalid certificate", "err", err)
			return false, time.Time{}
		}
		// if no error, certs[0] is the leaf cert (or self-signed cert)
		matches, err := cmutilpki.PublicKeyMatchesCertificate(pk, certs[0])
		if err != nil {
			log.V(5).Info("Couldn't check if Route private key matches Route certificate", "err", err)
			return false, time.Time{}
		}
		if !matches {
			log.V(5).Info("Route private key doesn't match route cert")
			return false, time.Time{}
		}
		// if we get here, we have a matching TLS cert/key pair.
		// See if the cert will expire soon.
		start := certs[0].NotBefore
		end := certs[0].NotAfter
		lifetime := end.Sub(start)
		remaining := end.Sub(time.Now())
		if remaining <= lifetime/3 {
			return false, time.Time{}
		}
		return true, start.Add(2 * lifetime / 3)
	}(instance)

	if upToDate {
		return c.ManageSuccessWithRequeue(ctx, instance, renewalTime.Sub(time.Now()))
	}

	// If we get here we need to fire off a certificate request. First step is to generate a new
	// private key.
	nextPrivateKeyPEM, found := instance.GetAnnotations()[cmapi.IsNextPrivateKeySecretLabelKey]
	if !found {
		// Generate a new private key, then re-reconcile.
		// TODO: make key type and size configurable with an annotation
		pk, err := cmutilpki.GenerateRSAPrivateKey(cmutilpki.MinRSAKeySize)
		if err != nil {
			return c.ManageError(ctx, instance, err)
		}
		pkPEM, err := cmutilpki.EncodePrivateKey(pk, cmapi.PKCS1)
		if err != nil {
			return c.ManageError(ctx, instance, err)
		}
		instance.GetAnnotations()[cmapi.IsNextPrivateKeySecretLabelKey] = string(pkPEM)
		err = c.GetClient().Update(ctx, instance)
		if err != nil {
			return c.ManageError(ctx, instance, err)
		}
		return c.ManageSuccess(ctx, instance)
	}
	// Is the Private Key malformed?
	pk, err := cmutilpki.DecodePrivateKeyBytes([]byte(nextPrivateKeyPEM))
	if err != nil {
		log.V(5).Error(err, "next private key annotation doesn't contain a valid key")
		delete(instance.GetAnnotations(), cmapi.IsNextPrivateKeySecretLabelKey)
		err = c.GetClient().Update(ctx, instance)
		if err != nil {
			return c.ManageError(ctx, instance, err)
		}
		return c.ManageSuccess(ctx, instance)
	}

	// We have a private key. Look for matching CertificateRequests
	certificateRequests := &cmapi.CertificateRequestList{}
	err = c.GetClient().List(ctx, certificateRequests, client.InNamespace(instance.Namespace))
	if err != nil {
		return c.ManageError(ctx, instance, err)
	}
	// only consider CertificateRequests that match the private key and are owned by this route
	var ownedCRs []*cmapi.CertificateRequest
	for _, cr := range certificateRequests.Items {
		x509CR, err := x509.ParseCertificateRequest(cr.Spec.Request)
		if err != nil {
			continue
		}
		matches, err := cmutilpki.PublicKeyMatchesCSR(pk.Public(), x509CR)
		if matches && err == nil {
			for _, or := range cr.OwnerReferences {
				if or.Kind == "Route" && or.Name == instance.Name {
					ownedCRs = append(ownedCRs, cr.DeepCopy())
					break
				}
			}
		}
	}
	// only consider the most recent CR
	sort.Slice(ownedCRs, func(i, j int) bool {
		return ownedCRs[i].CreationTimestamp.Time.After(ownedCRs[j].CreationTimestamp.Time)
	})

	// Possible states:
	switch {
	// no CR exists. Create a CR
	case len(ownedCRs) == 0:
		cr, err := c.certificateRequestFromRoute(instance, pk)
		if err != nil {
			return c.ManageError(ctx, instance, err)
		}
		err = c.GetClient().Create(ctx, cr)
		if err != nil {
			return c.ManageError(ctx, instance, err)
		}
		return c.ManageSuccess(ctx, instance)
	// CR has been explicitly denied. Not much we can do here.
	case cmutil.CertificateRequestIsDenied(ownedCRs[0]):
		log.Info("Not updating route as Certificate Request has been explicitly denied")
		c.GetRecorder().Event(
			instance,
			corev1.EventTypeWarning,
			cmapi.CertificateRequestReasonDenied,
			"Not updating route as Certificate Request has been explicitly denied",
		)
		return c.ManageSuccess(ctx, instance)

	// CR is invalid. We can't reconcile the Route either.
	case cmutil.CertificateRequestHasCondition(ownedCRs[0], cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionInvalidRequest,
		Status: "True",
	}):
		log.Info("Not updating route as Certificate Request has been rejected by the Issuer")
		c.GetRecorder().Event(
			instance,
			corev1.EventTypeWarning,
			cmapi.CertificateRequestReasonDenied,
			"Not updating route as Certificate Request has been rejected by the Issuer",
		)
		return c.ManageSuccess(ctx, instance)
	// CR is ready. Copy the cert/ca into the route.
	case cmutil.CertificateRequestHasCondition(ownedCRs[0], cmapi.CertificateRequestCondition{
		Type:               cmapi.CertificateRequestConditionReady,
		Status:             "True",
	}):
		instance.Spec.TLS.Key = nextPrivateKeyPEM
		delete(instance.Annotations, cmapi.IsNextPrivateKeySecretLabelKey)
		instance.Spec.TLS.Certificate = string(ownedCRs[0].Status.Certificate)
		if len(ownedCRs[0].Status.CA) > 0 {
			instance.Spec.TLS.CACertificate = string(ownedCRs[0].Status.CA)
		}
		err = c.GetClient().Update(ctx, instance)
		if err != nil {
			return c.ManageError(ctx, instance, err)
		}
		return c.ManageSuccess(ctx, instance)
	// No conditions that we know about, or issuance is in progress, just wait
	default:
		return c.ManageSuccess(ctx, instance)
	}
}

// hasCertManagerAnnotations is used in a predicate for our controller-runtime
// controller. Both the Issuer name and kind must be set for us to do anything
// useful with the route.
func hasCertManagerAnnotations(route *routev1.Route) bool {
	_, hasIssuerName := route.GetAnnotations()[cmapi.IssuerNameAnnotationKey]
	_, hasIssuerKind := route.GetAnnotations()[cmapi.IssuerKindAnnotationKey]
	return hasIssuerName && hasIssuerKind
}

func (c *CertificateRequestReconciler) certificateRequestFromRoute(route *routev1.Route, pk crypto.PrivateKey) (*cmapi.CertificateRequest, error) {
	x509CR := &x509.CertificateRequest{
		Version: 0,
		// TODO: make signature type and size configurable with an annotation
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKeyAlgorithm: x509.RSA,
		Subject: pkix.Name{
			CommonName: route.Spec.Host,
		},
		DNSNames: []string{route.Spec.Host},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, x509CR, pk)
	if err != nil {
		return nil, err
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})
	issuerRef := cmmeta.ObjectReference{}
	issuerName, hasIssuer := route.GetAnnotations()[cmapi.IssuerNameAnnotationKey]
	if hasIssuer {
		issuerRef.Name = issuerName
	}
	issuerKind, hasIssuerKind := route.GetAnnotations()[cmapi.IssuerKindAnnotationKey]
	if hasIssuerKind {
		issuerRef.Kind = issuerKind
	}
	issuerGroup, hasIssuerGroup := route.GetAnnotations()[cmapi.IssuerGroupAnnotationKey]
	if hasIssuerGroup {
		issuerRef.Group = issuerGroup
	} else {
		issuerRef.Group = cmapi.SchemeGroupVersion.Group
	}
	groupName, hasGroup := route.GetAnnotations()[cmapi.IssuerGroupAnnotationKey]
	if hasGroup {
		issuerRef.Group = groupName
	} else {
		issuerRef.Group = "cert-manager.io"
	}

	return &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: route.Name + "-",
			Namespace:    route.Namespace,
			Labels:       route.Labels,
			Annotations:  route.Annotations,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(route, routev1.SchemeGroupVersion.WithKind("Route")),
			},
		},
		Spec: cmapi.CertificateRequestSpec{
			Duration:  &metav1.Duration{Duration: cmapi.DefaultCertificateDuration},
			IssuerRef: issuerRef,
			Request:   csrPEM,
			IsCA:      false,
		},
	}, nil
}

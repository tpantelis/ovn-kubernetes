// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package tls

import (
	"context"
	"crypto/tls"
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
	openshifttls "github.com/openshift/controller-runtime-common/pkg/tls"
	"github.com/openshift/library-go/pkg/crypto"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"
	"k8s.io/klog/v2"
)

// GetConfigFromAPIServer fetches the TLS security profile from apiserver.config.openshift.io/cluster
// and converts it to a tls.Config.
//
// This implements OCP 4.23 TLS profile compliance by fetching the cluster's TLS profile
// and applying it using the official controller-runtime-common/pkg/tls package.
func GetConfigFromAPIServer(ctx context.Context, dynamicClient dynamic.Interface) (*tls.Config, error) {
	// Fetch the API Server configuration to get the TLS security profile
	apiServerGVR := configv1.GroupVersion.WithResource("apiservers")

	unstructuredAPIServer, err := dynamicClient.Resource(apiServerGVR).Get(ctx, openshifttls.APIServerName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch apiserver.config.openshift.io/%s: %w", openshifttls.APIServerName, err)
	}

	// Convert unstructured to typed APIServer object
	apiServer := &configv1.APIServer{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(unstructuredAPIServer.Object, apiServer); err != nil {
		return nil, fmt.Errorf("failed to convert APIServer from unstructured: %w", err)
	}

	// Get TLS profile spec from API Server configuration using official OpenShift package
	profileSpec, err := openshifttls.GetTLSProfileSpec(apiServer.Spec.TLSSecurityProfile)
	if err != nil {
		return nil, fmt.Errorf("failed to get TLS profile spec: %w", err)
	}

	// Convert profile spec to tls.Config using official OpenShift package
	// This handles TLS 1.3 correctly (only sets CipherSuites when MinVersion != TLS 1.3)
	tlsConfigFunc, unsupportedCiphers := openshifttls.NewTLSConfigFromProfile(profileSpec)

	// Log warnings for any unsupported ciphers
	for _, cipher := range unsupportedCiphers {
		klog.Warningf("Cipher suite %q not available in this Go version, skipping", cipher)
	}

	// Create and configure tls.Config
	tlsConfig := &tls.Config{}
	tlsConfigFunc(tlsConfig)

	// Validate that cipher filtering didn't leave us with an empty list for pre-TLS 1.3.
	// An empty CipherSuites with TLS 1.0-1.2 causes Go to fall back to its defaults,
	// which would bypass the cluster's TLS security profile.
	if tlsConfig.MinVersion < tls.VersionTLS13 {
		profileCipherCount := len(profileSpec.Ciphers)
		actualCipherCount := len(tlsConfig.CipherSuites)

		if profileCipherCount > 0 && actualCipherCount == 0 {
			return nil, fmt.Errorf("API Server TLS profile specified %d cipher suites but none are supported by this Go version",
				profileCipherCount)
		}
	}

	klog.Infof("Applied TLS profile from API Server: MinVersion=%s, CipherSuites=%d",
		crypto.TLSVersionToNameOrDie(tlsConfig.MinVersion), len(tlsConfig.CipherSuites))

	return tlsConfig, nil
}

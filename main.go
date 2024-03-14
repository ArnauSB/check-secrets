package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os/exec"
	"strings"

	"istio.io/istio/pkg/kube"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

func main() {
	// Get k8s clients
	kclient, dclient, err := k8sClient()
	if err != nil {
		fmt.Println("error creating the k8s clients:", err)
		return
	}

	// Get namespaces list
	nsList, err := getNamespaces(kclient)
	if err != nil {
		fmt.Println("error getting the list of namespaces:", err)
		return
	}

	// Get resources per namespace
	err = getNsGateways(kclient, dclient, nsList)
	if err != nil {
		fmt.Println("error getting resources per namespace:", err)
		return
	}
}

func k8sClient() (*kubernetes.Clientset, dynamic.Interface, error) {
	clientcfg := kube.BuildClientCmd("", "")
	restConfig, err := clientcfg.ClientConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get k8s config file: %v", err)
	}

	k8sClient, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create k8s client: %v", err)
	}

	k8sDynClient, err := dynamic.NewForConfig(restConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create k8s dynamic client: %v", err)
	}

	return k8sClient, k8sDynClient, nil
}

func getNamespaces(kclient *kubernetes.Clientset) ([]string, error) {
	var nsNames []string
	nsList, err := kclient.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to get the list of namespaces: %v", err)
	}

	for _, ns := range nsList.Items {
		if ns.Name != "kube-system" && ns.Name != "xcp-multicluster" {
			nsNames = append(nsNames, ns.Name)
		}
	}

	return nsNames, nil
}

func getNsGateways(kclient *kubernetes.Clientset, dclient dynamic.Interface, nsList []string) error {
	var (
		gwNum int
	)

	gwRes := schema.GroupVersionResource{
		Group:    "networking.istio.io",
		Version:  "v1alpha3",
		Resource: "gateways",
	}

	for _, ns := range nsList {
		// Get gateways per namespace
		gwList, err := dclient.Resource(gwRes).Namespace(ns).List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			return err
		}
		gwNum = len(gwList.Items)

		if gwNum > 0 {
			// Iterate over each gateway
			for _, gw := range gwList.Items {
				// Get secrets per gateway
				secrets, err := getGatewaySecrets(kclient, gw)
				if err != nil {
					fmt.Printf("error getting secrets for gateway in namespace %s: %v\n", ns, err)
					continue
				}

				if len(secrets) > 0 {
					// Analyze and print certificate expiration for each secret
					for _, secret := range secrets {
						expiryDate, err := analyzeCertificate(secret)
						if err != nil {
							fmt.Printf("error analyzing certificate for gateway %s in namespace %s: %v\n", gw.GetName(), ns, err)
							continue
						}

						fmt.Printf("Certificate %s in gateway %s in namespace %s expiration date is %s\n", secret.GetName(), gw.GetName(), ns, expiryDate)
					}
				}
			}
		}
	}

	return nil
}

func getGatewaySecrets(kclient *kubernetes.Clientset, gw unstructured.Unstructured) ([]corev1.Secret, error) {
	var secrets []corev1.Secret

	// Iterate over the gateway's servers
	servers, found, err := unstructured.NestedSlice(gw.Object, "spec", "servers")
	if !found || err != nil {
		return nil, fmt.Errorf("error getting gateway servers: %v", err)
	}

	for _, serverObj := range servers {
		server, ok := serverObj.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("invalid server object found")
		}

		// Check if the server has a secretName defined
		tls, found, err := unstructured.NestedMap(server, "tls")
		if !found || err != nil {
			continue // No TLS configuration found
		}

		mode, found, err := unstructured.NestedString(tls, "mode")
		if !found || err != nil || mode == "PASSTHROUGH" {
			continue // TLS mode is PASSTHROUGH, skip
		}

		credentialName, found, err := unstructured.NestedString(tls, "credentialName")
		if !found || err != nil {
			continue // No credentialName found
		}

		// Get the secret
		secret, err := kclient.CoreV1().Secrets(gw.GetNamespace()).Get(context.TODO(), credentialName, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("error getting secret %s in namespace %s: %v", credentialName, gw.GetNamespace(), err)
		}

		// Append the secret to the list
		secrets = append(secrets, *secret)
	}

	return secrets, nil
}

func analyzeCertificate(secret corev1.Secret) (string, error) {
	// Extract the certificate data from the secret
	certData, ok := secret.Data["tls.crt"]
	if !ok {
		return "", fmt.Errorf("tls.crt not found in secret")
	}

	// Remove begin and end
	certData = bytes.ReplaceAll(certData, []byte("-----BEGIN CERTIFICATE-----\n"), []byte{})
	certData = bytes.ReplaceAll(certData, []byte("\n-----END CERTIFICATE-----"), []byte{})

	// Decode the base64-encoded certificate data
	certBytes, err := base64.StdEncoding.DecodeString(string(certData))
	if err != nil {
		return "", fmt.Errorf("error decoding certificate data: %v", err)
	}

	// Execute OpenSSL command to analyze the certificate
	opensslCmd := exec.Command("openssl", "x509", "-noout", "-enddate")
	opensslCmd.Stdin = bytes.NewReader(certBytes)
	output, err := opensslCmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("openssl error: %v", err)
	}

	// Extract the expiration date from the OpenSSL output
	expiryDate := strings.TrimSpace(strings.TrimPrefix(string(output), "notAfter="))

	return expiryDate, nil
}

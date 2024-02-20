package cache

import (
	"time"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	kcache "k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	clog "github.com/coredns/coredns/plugin/pkg/log"
)

type k8sAPI struct {
	// Client cache for the Kubernetes API
	store         kcache.Store
	reflector     *kcache.Reflector
	reflectorChan chan struct{}

	// Kubernetes credentials (copied from Kubernetes plugin)
	APIServerList []string
	APICertAuth   string
	APIClientCert string
	APIClientKey  string
}

func newK8sAPI() (*k8sAPI, error) {
	k := new(k8sAPI)
	clientset, err := k.getKubernetesClient()
	if err != nil {
		return k, err
	}

	optionsModifier := func(options *metav1.ListOptions) {
		options.LabelSelector = "k8s-cache.coredns.io/early-refresh=true"
	}
	lw := kcache.NewFilteredListWatchFromClient(
		clientset.CoreV1().RESTClient(),
		"pods",
		metav1.NamespaceAll,
		optionsModifier,
	)

	k.store, k.reflector = kcache.NewNamespaceKeyedIndexerAndReflector(lw, &v1.Pod{}, time.Second*10)
	k.reflectorChan = make(chan struct{})
	go k.reflector.Run(k.reflectorChan)

	return k, nil
}

func (k *k8sAPI) getKubernetesClient() (*kubernetes.Clientset, error) {
	config, err := k.getClientConfig()
	if err != nil {
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return clientset, nil
}

// Copied from the getClientConfig method of the kubernetes plugin
func (k *k8sAPI) getClientConfig() (*rest.Config, error) {
	loadingRules := &clientcmd.ClientConfigLoadingRules{}
	overrides := &clientcmd.ConfigOverrides{}
	clusterinfo := clientcmdapi.Cluster{}
	authinfo := clientcmdapi.AuthInfo{}

	// Connect to API from in cluster
	if len(k.APIServerList) == 0 {
		cc, err := rest.InClusterConfig()
		if err != nil {
			return nil, err
		}
		cc.ContentType = "application/vnd.kubernetes.protobuf"
		return cc, err
	}

	// Connect to API from out of cluster
	// Only the first one is used. We will deprecate multiple endpoints later.
	clusterinfo.Server = k.APIServerList[0]

	if len(k.APICertAuth) > 0 {
		clusterinfo.CertificateAuthority = k.APICertAuth
	}
	if len(k.APIClientCert) > 0 {
		authinfo.ClientCertificate = k.APIClientCert
	}
	if len(k.APIClientKey) > 0 {
		authinfo.ClientKey = k.APIClientKey
	}

	overrides.ClusterInfo = clusterinfo
	overrides.AuthInfo = authinfo
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, overrides)

	cc, err := clientConfig.ClientConfig()
	if err != nil {
		return nil, err
	}
	cc.ContentType = "application/vnd.kubernetes.protobuf"
	return cc, err
}

// Get all IP addresses of all pods selected by k.reflector, i.e. those who should receive early cache refreshes.
func (k *k8sAPI) getEarlyRefreshIPs() []string {
	items := k.store.List()
	ips := make([]string, 0, len(items))
	for _, item := range items {
		pod, ok := item.(*v1.Pod)
		if !ok {
			log := clog.NewWithPlugin("k8s_cache")
			log.Errorf("Cache item is not a *v1.Pod")
			return nil
		}
		for ip := range pod.Status.PodIPs {
			ips = append(ips, pod.Status.PodIPs[ip].IP)
		}
	}
	return ips
}

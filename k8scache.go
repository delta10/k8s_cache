package cache 

import (
	"time"

	"github.com/coredns/coredns/plugin/pkg/cache"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

type Cache struct {
	*CacheBackend

	// Late positive cache. CacheBackend.pcache is the early cache
	latepcache  *cache.Cache
	extrattl		time.Duration

	k8sAPI *k8sAPI
}

func New() *Cache {
	cb := NewBackend()
	return &Cache{
		CacheBackend: cb,
		latepcache: cache.New(defaultCap),
		k8sAPI: &k8sAPI{},
	}
}

// Copy item to c.latepcache if the conditions are right
func (c *Cache) copyToLate(key uint64, i *item, now time.Time) {
	if i.Rcode == dns.RcodeSuccess  {
		ii, exists := c.latepcache.Get(key)
		add := false
		if exists {
			li := ii.(*item)
			if li.ttl(now) <= 0 {
				add = true
			}
		} else {
			add = true
		}
		if add {
			newi := *i
			newi.origTTL += uint32(c.extrattl.Seconds())
			c.latepcache.Add(key, &newi)
		}
	}
}

// Get cache item for c.ncache or c.pcache (early cache). Only ncache item can be stale
func (c *Cache) getEarly(now time.Time, state request.Request, server string) *item {
	k := hash(state.Name(), state.QType(), state.Do(), state.Req.CheckingDisabled)

	if i, ok := c.ncache.Get(k); ok {
		itm := i.(*item)
		ttl := itm.ttl(now)
		if itm.matches(state) && (ttl > 0 || (c.staleUpTo > 0 && -ttl < int(c.staleUpTo.Seconds()))) {
			cacheHits.WithLabelValues(server, Denial, c.zonesMetricLabel, c.viewMetricLabel).Inc()
			return i.(*item)
		}
	}
	if i, ok := c.pcache.Get(k); ok {
		itm := i.(*item)
		ttl := itm.ttl(now)
		if itm.matches(state) && ttl > 0 {
			cacheHits.WithLabelValues(server, Success, c.zonesMetricLabel, c.viewMetricLabel).Inc()
			return i.(*item)
		}
	}
	cacheMisses.WithLabelValues(server, c.zonesMetricLabel, c.viewMetricLabel).Inc()
	return nil
}

func (c *Cache) getLate(now time.Time, state request.Request, server string) *item {
	k := hash(state.Name(), state.QType(), state.Do(), state.Req.CheckingDisabled)
	cacheRequests.WithLabelValues(server, c.zonesMetricLabel, c.viewMetricLabel).Inc()

	if i, ok := c.latepcache.Get(k); ok {
		itm := i.(*item)
		ttl := itm.ttl(now)
		staleupto := c.staleUpTo - c.extrattl
		if itm.matches(state) && (ttl > 0 || (staleupto > 0 && -ttl < int(staleupto.Seconds()))) {
			cacheHits.WithLabelValues(server, Success, c.zonesMetricLabel, c.viewMetricLabel).Inc()
			return i.(*item)
		}
	}
	return nil
}

func (c *Cache) NeedEarlyRefresh(state request.Request) bool {
	earlyips := c.k8sAPI.getEarlyRefreshIPs()
	me := state.IP()
	for _, ip := range earlyips {
			if ip == me {
				return true
			}
	}
	return false
}

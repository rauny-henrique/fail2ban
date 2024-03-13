package fail2ban

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/rauny-henrique/fail2ban/log"
)

// Config passed in from traefik configuration
type Config struct {
	NumberFails  uint
	BanTime      string
	ClientHeader string
	LogLevel     log.LogLevel
}

// Create config with reasonable defaults
func CreateConfig() *Config {
	return &Config{
		NumberFails:  3,
		BanTime:      "3h",
		ClientHeader: "Cf-Connecting-IP",
		LogLevel:     log.Info,
	}
}

type fail2Ban struct {
	// Boilerplate stuff
	next   http.Handler
	name   string
	logger *log.Logger

	// Stuff specific to this plugin
	maxFails      uint
	banTime       time.Duration
	clientHeader  string
	bannedClients map[string]*client
	// mutex is specifically access the bannedClients map
	mu sync.Mutex

	// this is a test var to signal cleaner is running
	_cleaning_test_var bool
}

func New(ctx context.Context, next http.Handler, config *Config, middleWareName string) (http.Handler, error) {
	duration, err := time.ParseDuration(config.BanTime)
	if err != nil {
		return nil, err
	}
	f := fail2Ban{
		name:          middleWareName,
		logger:        log.New("Fail-2-Ban", config.LogLevel),
		next:          next,
		maxFails:      config.NumberFails,
		clientHeader:  config.ClientHeader,
		banTime:       duration,
		bannedClients: make(map[string]*client),
	}
	f.logger.Infof("Max Number Failures %d, Ban Time %q, Client-ID-header %q", f.maxFails, f.banTime, f.clientHeader)
	go f.cleaner(ctx)

	return &f, err
}

func (f *fail2Ban) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	client, err := f.extractClient(req)
	if err != nil {
		f.logger.Errorf("Failed to get Client Identifier due to %q, blocking request to be safe", err)
		rw.WriteHeader(http.StatusForbidden)
		return

	}
	f.logger.Debugf("Request from %s", client)

	// block request if client has been banned
	if f.isClientBanned(client) {
		rw.WriteHeader(http.StatusForbidden)
		return
	}

	// intercept returned status code from downstream service(s)
	i := newIntercept(rw)
	f.next.ServeHTTP(i, req)

	// check for 4xx class status code
	if i.checkBadUserRequestStatusCode() {
		f.incrementViewCounter(client)
	}
}

func (f *fail2Ban) isClientBanned(ip string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logger.Debugf("Checking for %s", ip)
	if c, ok := f.bannedClients[ip]; !ok {
		return false
	} else if c.failCounter >= f.maxFails {
		// Un-ban
		if c.hasBanExpired(time.Now(), f.banTime) {
			f.logger.Infof("Un-Banned %s", ip)
			delete(f.bannedClients, ip)
		} else {
			// extend Ban
			f.logger.Infof("Extend Ban for %s", ip)
			c.failCounter++
			c.lastViewed = time.Now()
			return true
		}
	}
	return false
}

func (f *fail2Ban) incrementViewCounter(ip string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logger.Debugf("Increment %s", ip)
	if f.bannedClients[ip] == nil {
		f.bannedClients[ip] = &client{
			failCounter: 1,
		}
		return
	}
	f.bannedClients[ip].lastViewed = time.Now()
	f.bannedClients[ip].failCounter++
}

// periodically clean up banned clients
func (f *fail2Ban) cleaner(ctx context.Context) {
	timer := time.NewTimer(f.banTime / 4)
	for {
		select {
		case <-ctx.Done():
			f.logger.Info("Shutting down client cleaner")
			f._cleaning_test_var = false
			return
		case <-timer.C:
			f.logger.Debugf("Cleaning up stale client states...")
			f.mu.Lock()
			f._cleaning_test_var = true
			{
				now := time.Now()
				for ip, c := range f.bannedClients {
					if c.hasBanExpired(now, f.banTime) {
						f.logger.Infof("Clearing out state for %s, it is no longer banned", ip)
						delete(f.bannedClients, ip)
					} else {
						f.logger.Debugf("%s still needs to be tracked", ip)
					}
				}
			}
			f.mu.Unlock()
		}
		timer.Reset(f.banTime / 4)
	}
}

func (f *fail2Ban) extractClient(req *http.Request) (string, error) {
	if len(f.clientHeader) > 0 {
		client := req.Header.Get(f.clientHeader)
		if len(client) != 0 {
			return client, nil
		}
	}
	if client, _, err := net.SplitHostPort(req.RemoteAddr); err != nil {
		return "", fmt.Errorf("failed to extract Client IP from RemoteAddr: %w", err)
	} else {
		return client, nil
	}
}

// Intercept Return code from downstream
type interceptor struct {
	http.ResponseWriter
	code int
}

func newIntercept(w http.ResponseWriter) *interceptor {
	return &interceptor{w, http.StatusAccepted}
}

// Check for for 4xx status code (bad user requests)
func (i *interceptor) checkBadUserRequestStatusCode() bool {
	return i.code >= http.StatusBadRequest && i.code < http.StatusInternalServerError
}

func (i *interceptor) WriteHeader(code int) {
	i.code = code
	i.ResponseWriter.WriteHeader(code)
}

// client data tracking struct
type client struct {
	lastViewed  time.Time
	failCounter uint
}

func (c client) hasBanExpired(currentTime time.Time, d time.Duration) bool {
	return currentTime.After(c.lastViewed.Add(d))
}

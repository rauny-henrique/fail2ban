package fail2ban

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"
)

type Config struct {
	NumberFails  uint
	BanTime      string
	ClientHeader string
}

func CreateConfig() *Config {
	return &Config{
		NumberFails:  3,
		BanTime:      "3h",
		ClientHeader: "Cf-Connecting-IP",
	}
}

type client struct {
	lastViewed  time.Time
	failCounter uint
}

func (c client) nextAllowedView(d time.Duration) time.Time {
	return c.lastViewed.Add(d)
}

type fail2Ban struct {
	next http.Handler
	name string

	logger *slog.Logger
	mu     sync.Mutex

	maxFails      uint
	banTime       time.Duration
	clientHeader  string
	bannedClients map[string]*client
}

func New(ctx context.Context, next http.Handler, config *Config, middleWareName string) (http.Handler, error) {
	duration, err := time.ParseDuration(config.BanTime)
	f := fail2Ban{
		name:          middleWareName,
		logger:        slog.New(slog.NewJSONHandler(os.Stdout, nil)),
		next:          next,
		maxFails:      config.NumberFails,
		clientHeader:  config.ClientHeader,
		banTime:       duration,
		bannedClients: make(map[string]*client),
	}
	f.logger.Info(fmt.Sprintf("Max Number Failures %d, Ban Time %s, Client-ID-header %s", f.maxFails, f.banTime, f.clientHeader))
	if err == nil {
		go f.cleaner(ctx)
	}

	return &f, err
}

// Intercept Return code from downstream
type interceptor struct {
	http.ResponseWriter
	code int
}

func newIntercept(w http.ResponseWriter) *interceptor {
	return &interceptor{w, http.StatusAccepted}
}

func (i *interceptor) WriteHeader(code int) {
	i.code = code
	i.ResponseWriter.WriteHeader(code)
}

func (f *fail2Ban) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	client := req.Header.Get(f.clientHeader)
	f.logger.Debug(fmt.Sprintf("Request from %s", client))

	if f.checkViewCounter(client) {
		rw.WriteHeader(http.StatusForbidden)
		return
	}

	i := newIntercept(rw)
	f.next.ServeHTTP(i, req)

	if i.code >= 400 && i.code < 500 {
		f.incrementViewCounter(client)
	}
}

func (f *fail2Ban) checkViewCounter(ip string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logger.Debug(fmt.Sprintf("Checking for %s", ip))
	if c, ok := f.bannedClients[ip]; !ok {
		return false
	} else if c.failCounter >= f.maxFails {
		// Un-ban
		if time.Now().After(c.nextAllowedView(f.banTime)) {
			f.logger.Info(fmt.Sprintf("Un-Banned %s", ip))
			delete(f.bannedClients, ip)
		} else {
			// extend Ban
			f.logger.Info(fmt.Sprintf("Extend Ban for %s", ip))
			c.failCounter++
			c.lastViewed = time.Now()
			f.bannedClients[ip] = c
			return true
		}
	}
	return false
}

func (f *fail2Ban) incrementViewCounter(ip string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logger.Debug(fmt.Sprintf("Increment %s", ip))
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
			return
		case <-timer.C:
			f.logger.Debug("Cleaning up stale clients...")
			f.mu.Lock()
			{
				now := time.Now()
				for ip, c := range f.bannedClients {
					if now.After(c.nextAllowedView(f.banTime)) {
						f.logger.Info(fmt.Sprintf("%s is no longer banned", ip))
						c = nil
						delete(f.bannedClients, ip)
					} else {
						f.logger.Debug(fmt.Sprintf("%s is still banned", ip))
					}
				}
			}
			f.mu.Unlock()
		}
		timer.Reset(f.banTime / 4)
	}
}

package fail2ban

import (
	"context"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

type Config struct {
	NumberFails uint
	BanTime     string
}

func CreateConfig() *Config {
	return &Config{
		NumberFails: 3,
		BanTime:     "3h",
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

	logger *log.Logger
	mu     sync.Mutex

	maxFails      uint
	banTime       time.Duration
	bannedClients map[string]*client
}

func New(ctx context.Context, next http.Handler, config *Config, middleWareName string) (http.Handler, error) {
	duration, err := time.ParseDuration(config.BanTime)
	f := fail2Ban{
		name:          middleWareName,
		logger:        log.New(os.Stdout, "[FAIL 2 BAN] ", log.Ldate|log.Ltime),
		next:          next,
		maxFails:      config.NumberFails,
		banTime:       duration,
		bannedClients: make(map[string]*client),
	}
	f.logger.Printf("Max Number Failures %d, Ban Time %s\n", f.maxFails, f.banTime)
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
	client, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		rw.WriteHeader(http.StatusForbidden)
		return
	}
	f.logger.Println("Request from ", client)

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
	f.logger.Println("Check")
	if c, ok := f.bannedClients[ip]; !ok {
		return false
	} else if c.failCounter >= f.maxFails {
		// Un-ban
		if time.Now().After(c.nextAllowedView(f.banTime)) {
			f.logger.Println("Unban")
			delete(f.bannedClients, ip)
		} else {
			// extend Ban
			f.logger.Println("Extend")
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
	f.logger.Println("Increment ", ip)
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
			f.logger.Println("Cleaning up stale clients...")
			f.mu.Lock()
			{
				now := time.Now()
				for ip, c := range f.bannedClients {
					if now.After(c.nextAllowedView(f.banTime)) {
						f.logger.Println(ip, " is no longer banned")
						c = nil
						delete(f.bannedClients, ip)
					} else {
						f.logger.Println(ip, " is still banned")
					}
				}
			}
			f.mu.Unlock()
		}
		timer.Reset(f.banTime / 4)
	}
}
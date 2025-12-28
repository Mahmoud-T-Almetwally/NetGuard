package packet

import (
	"github.com/florianl/go-nfqueue"
	"netguard/internal/engine"
	"log"
	"context"
)

type Listener struct {
	Config nfqueue.Config
	Nfq* nfqueue.Nfqueue
}

func (l* Listener) Start(ctx context.Context, e* engine.Engine, cfg nfqueue.Config) error {

	nfq, err := nfqueue.Open(&cfg)
	if err != nil {
		log.Printf("Could Not Open nfqueue socket: %v", err)
		return err
	}

	l.Config = cfg
	l.Nfq = nfq

	fn := func(a nfqueue.Attribute) int {
		id := *a.PacketID
		
		// Extract Payload (Raw Bytes)
		// This is what you will eventually pass to gopacket
		var payload []byte
		if a.Payload != nil {
			payload = *a.Payload
		}

		domain, found := ExtractDomain(payload)

		if found {
			shouldBlock, err := e.Decision(domain)
			if err != nil {
				log.Printf("Decision on Domain failed: %v", err)
			}

			if shouldBlock {
				l.Nfq.SetVerdict(id, nfqueue.NfDrop)
				log.Printf("Id: %d, Domain: %s, Length: %d, Verdict: BLOCKED", id, domain, len(payload))
				return 0
			}
			
			// log.Printf("Id: %d, Domain: %s, Length: %d, Verdict: ACCEPTED", id, domain, len(payload))

		}
		
		// Default -> accept
		l.Nfq.SetVerdict(id, nfqueue.NfAccept)
		return 0
	}

	errFn := func(e error) int {
		log.Printf("NFQueue Error: %v", e)
		return 0
	}

	if err := l.Nfq.RegisterWithErrorFunc(ctx, fn, errFn); err != nil {
		log.Printf("Could Not Register hook: %v", err)
		return err
	}

	return nil
}
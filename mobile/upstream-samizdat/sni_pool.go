package samizdat

// Default Russian-cover SNI pool (compass v2 §5.7 / §3.10). Curated subset
// of high-traffic RU sites that:
//   - Are in the Roskomnadzor "socially significant services" whitelist (never
//     blocked even during regional shutdowns or mobile-whitelist regimes).
//   - Appear in Tranco Top 100K with high RU traffic share.
//   - Use HTTPS on :443 with stable cert chains (cover-handshake works).
//
// Weights approximate Zipf distribution of real browser visit frequency:
// the top entry gets weight 100, rank N gets ~100/N. Picking weighted-random
// from this list matches a real browser's per-SNI distribution far better
// than uniform-random over a 5-element pool.
//
// Config helper: operators can read this list via DefaultRussianCoverSNIs()
// and use it to populate ClientConfig.ServerNames + ServerConfig.MasqueradePool
// (mapping sni -> origin host, here always sni == origin since these are
// real domains we forward to).

type SNIEntry struct {
	SNI    string
	Weight int
}

// defaultRussianCoverSNIs is the curated pool. Order = approximate rank.
var defaultRussianCoverSNIs = []SNIEntry{
	{"yandex.ru", 100},
	{"vk.com", 90},
	{"mail.ru", 75},
	{"ok.ru", 65},
	{"rambler.ru", 35},
	{"avito.ru", 50},
	{"ozon.ru", 45},
	{"wildberries.ru", 40},
	{"sberbank.ru", 38},
	{"gosuslugi.ru", 35}, // RKN whitelist core
	{"rutube.ru", 30},
	{"dzen.ru", 28},
	{"market.yandex.ru", 25},
	{"mts.ru", 22},
	{"megafon.ru", 20},
	{"beeline.ru", 18},
	{"tele2.ru", 16},
	{"rt.ru", 15},
	{"pochta.ru", 14},
	{"nalog.gov.ru", 12},
	{"kinopoisk.ru", 22},
	{"hh.ru", 20},
	{"lenta.ru", 18},
	{"ria.ru", 17},
	{"tass.ru", 15},
	{"rg.ru", 13},
	{"kommersant.ru", 12},
	{"vedomosti.ru", 11},
	{"rbc.ru", 14},
	{"mvideo.ru", 10},
	{"eldorado.ru", 9},
	{"dns-shop.ru", 9},
	{"kassir.ru", 7},
	{"afisha.ru", 7},
	{"pikabu.ru", 13},
	{"habr.com", 11},
	{"livejournal.com", 8},
	{"vc.ru", 7},
}

// DefaultRussianCoverSNIs returns a copy of the curated cover-SNI pool with
// approximate Zipf weights. Operators use this to populate
// ClientConfig.ServerNames (list form) and ServerConfig.MasqueradePool
// (sni -> origin map; for these entries origin == sni).
func DefaultRussianCoverSNIs() []SNIEntry {
	out := make([]SNIEntry, len(defaultRussianCoverSNIs))
	copy(out, defaultRussianCoverSNIs)
	return out
}

// DefaultRussianCoverSNINames returns just the SNI names from the pool.
// Convenience wrapper for ClientConfig.ServerNames assignment.
func DefaultRussianCoverSNINames() []string {
	out := make([]string, len(defaultRussianCoverSNIs))
	for i, e := range defaultRussianCoverSNIs {
		out[i] = e.SNI
	}
	return out
}

// DefaultRussianCoverMasqueradePool returns sni -> origin mapping (origin
// equals sni for these direct entries). Convenience wrapper for
// ServerConfig.MasqueradePool assignment.
func DefaultRussianCoverMasqueradePool() map[string]string {
	out := make(map[string]string, len(defaultRussianCoverSNIs))
	for _, e := range defaultRussianCoverSNIs {
		out[e.SNI] = e.SNI
	}
	return out
}

// pickWeightedSNI returns a weighted-random pick from the entries.
// Used by Client when ServerNames is empty AND CoverPoolMode=true.
func pickWeightedSNI(entries []SNIEntry) string {
	if len(entries) == 0 {
		return ""
	}
	total := 0
	for _, e := range entries {
		if e.Weight < 0 {
			continue
		}
		total += e.Weight
	}
	if total == 0 {
		return entries[0].SNI
	}
	r := int(coverRandUint64n(uint64(total)))
	cum := 0
	for _, e := range entries {
		cum += e.Weight
		if r < cum {
			return e.SNI
		}
	}
	return entries[len(entries)-1].SNI
}

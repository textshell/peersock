#include "peersock.h"

#include <chrono>
#include <random>
#include <string>
#include <string_view>
#include <type_traits>
#include <variant>

#include <glib.h>
#include <libsoup/soup.h>
#include <agent.h> // libnice
#include <fmt/core.h>
#include <nlohmann/json.hpp>
extern "C" {
#include <libotr/sm.h>
}

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include "utils.h"

using namespace std::string_literals;

//static const std::string_view mailboxServer = "ws://localhost:4000/v1";
static const std::string_view mailboxServer = "ws://relay.magic-wormhole.io/v1";
static const std::string_view appId = "peersock.namepad.de";
static const std::string_view clientVersion1 = "peersock";
static const std::string_view clientVersion2 = "0.0.1";

static const unsigned char alpn[] = { 10, 'x', '-', 'p', 'e', 'e', 'r', 's', 'o', 'c', 'k' };

std::function<void(std::string)> codeCallback;

static SSL *quicKeepaliveStream = nullptr; // stream 0
static std::string AuthStreamBuffer;
static SSL *quicAuthStream = nullptr; // stream 4

static SSL *quic_poll;
static SSL_CTX *quic_ssl_ctx;
static BIO *quic_dgram_bio;


enum class ShutdownState {
    noShutdown,
    shutdownPending,
    shutdownDone,
};

static ShutdownState in_shutdown;

static bool quicConnectionUp = false;
static int iceStreamId = -1;
static OtrlSMState authState;
static int authStep = 0;

// from code
static SSL *quic_client;


// server (initiator)
static SSL *quic_connection;

// ---

static void quicPoll();

class RemoteConnectionImpl : public RemoteConnection {
public:
    RemoteConnectionImpl(SSL *ssl) : _ssl(ssl) {}

public:
    SSL *ssl() override {
        return _ssl;
    }

    void shutdown() override {
        int ret = SSL_shutdown(_ssl);
        if (ret < 0) {
            fatal_ossl("SSL_shutdown failed:\n");
        }
        in_shutdown = ret ? in_shutdown = ShutdownState::shutdownDone : ShutdownState::shutdownPending;
        ::quicPoll();
    }

    SSL *_ssl = nullptr;
};

static std::array<std::string_view, 2048> words = {
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse", "access",
    "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act", "action", "actor",
    "actress", "actual", "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance", "advice", "aerobic",
    "affair", "afford", "afraid", "again", "age", "agent", "agree", "ahead", "aim", "air", "airport", "aisle", "alarm",
    "album", "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone", "alpha", "already", "also",
    "alter", "always", "amateur", "amazing", "among", "amount", "amused", "analyst", "anchor", "ancient", "anger",
    "angle", "angry", "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique", "anxiety",
    "any", "apart", "apology", "appear", "apple", "approve", "april", "arch", "arctic", "area", "arena", "argue", "arm",
    "armed", "armor", "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact", "artist", "artwork",
    "ask", "aspect", "assault", "asset", "assist", "assume", "asthma", "athlete", "atom", "attack", "attend", "attitude",
    "attract", "auction", "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado", "avoid", "awake",
    "aware", "away", "awesome", "awful", "awkward", "axis", "baby", "bachelor", "bacon", "badge", "bag", "balance",
    "balcony", "ball", "bamboo", "banana", "banner", "bar", "barely", "bargain", "barrel", "base", "basic", "basket",
    "battle", "beach", "bean", "beauty", "because", "become", "beef", "before", "begin", "behave", "behind", "believe",
    "below", "belt", "bench", "benefit", "best", "betray", "better", "between", "beyond", "bicycle", "bid", "bike",
    "bind", "biology", "bird", "birth", "bitter", "black", "blade", "blame", "blanket", "blast", "bleak", "bless",
    "blind", "blood", "blossom", "blouse", "blue", "blur", "blush", "board", "boat", "body", "boil", "bomb", "bone",
    "bonus", "book", "boost", "border", "boring", "borrow", "boss", "bottom", "bounce", "box", "boy", "bracket", "brain",
    "brand", "brass", "brave", "bread", "breeze", "brick", "bridge", "brief", "bright", "bring", "brisk", "broccoli",
    "broken", "bronze", "broom", "brother", "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb",
    "bulk", "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus", "business", "busy", "butter", "buyer",
    "buzz", "cabbage", "cabin", "cable", "cactus", "cage", "cake", "call", "calm", "camera", "camp", "can", "canal",
    "cancel", "candy", "cannon", "canoe", "canvas", "canyon", "capable", "capital", "captain", "car", "carbon",
    "card", "cargo", "carpet", "carry", "cart", "case", "cash", "casino", "castle", "casual", "cat", "catalog",
    "catch", "category", "cattle", "caught", "cause", "caution", "cave", "ceiling", "celery", "cement", "census",
    "century", "cereal", "certain", "chair", "chalk", "champion", "change", "chaos", "chapter", "charge", "chase",
    "chat", "cheap", "check", "cheese", "chef", "cherry", "chest", "chicken", "chief", "child", "chimney", "choice",
    "choose", "chronic", "chuckle", "chunk", "churn", "cigar", "cinnamon", "circle", "citizen", "city", "civil",
    "claim", "clap", "clarify", "claw", "clay", "clean", "clerk", "clever", "click", "client", "cliff", "climb",
    "clinic", "clip", "clock", "clog", "close", "cloth", "cloud", "clown", "club", "clump", "cluster", "clutch",
    "coach", "coast", "coconut", "code", "coffee", "coil", "coin", "collect", "color", "column", "combine", "come",
    "comfort", "comic", "common", "company", "concert", "conduct", "confirm", "congress", "connect", "consider",
    "control", "convince", "cook", "cool", "copper", "copy", "coral", "core", "corn", "correct", "cost", "cotton",
    "couch", "country", "couple", "course", "cousin", "cover", "coyote", "crack", "cradle", "craft", "cram", "crane",
    "crash", "crater", "crawl", "crazy", "cream", "credit", "creek", "crew", "cricket", "crime", "crisp", "critic",
    "crop", "cross", "crouch", "crowd", "crucial", "cruel", "cruise", "crumble", "crunch", "crush", "cry", "crystal",
    "cube", "culture", "cup", "cupboard", "curious", "current", "curtain", "curve", "cushion", "custom", "cute",
    "cycle", "dad", "damage", "damp", "dance", "danger", "daring", "dash", "daughter", "dawn", "day", "deal", "debate",
    "debris", "decade", "december", "decide", "decline", "decorate", "decrease", "deer", "defense", "define", "defy",
    "degree", "delay", "deliver", "demand", "demise", "denial", "dentist", "deny", "depart", "depend", "deposit",
    "depth", "deputy", "derive", "describe", "desert", "design", "desk", "despair", "destroy", "detail", "detect",
    "develop", "device", "devote", "diagram", "dial", "diamond", "diary", "dice", "diesel", "diet", "differ", "digital",
    "dignity", "dilemma", "dinner", "dinosaur", "direct", "dirt", "disagree", "discover", "disease", "dish", "dismiss",
    "disorder", "display", "distance", "divert", "divide", "divorce", "dizzy", "doctor", "document", "dog", "doll",
    "dolphin", "domain", "donate", "donkey", "donor", "door", "dose", "double", "dove", "draft", "dragon", "drama",
    "drastic", "draw", "dream", "dress", "drift", "drill", "drink", "drip", "drive", "drop", "drum", "dry", "duck",
    "dumb", "dune", "during", "dust", "dutch", "duty", "dwarf", "dynamic", "eager", "eagle", "early", "earn", "earth",
    "easily", "east", "easy", "echo", "ecology", "economy", "edge", "edit", "educate", "effort", "egg", "eight",
    "either", "elbow", "elder", "electric", "elegant", "element", "elephant", "elevator", "elite", "else", "embark",
    "embody", "embrace", "emerge", "emotion", "employ", "empower", "empty", "enable", "enact", "end", "endless",
    "endorse", "enemy", "energy", "enforce", "engage", "engine", "enhance", "enjoy", "enlist", "enough", "enrich",
    "enroll", "ensure", "enter", "entire", "entry", "envelope", "episode", "equal", "equip", "era", "erase", "erode",
    "erosion", "error", "erupt", "escape", "essay", "essence", "estate", "eternal", "ethics", "evidence", "evil", "evoke",
    "evolve", "exact", "example", "excess", "exchange", "excite", "exclude", "excuse", "execute", "exercise", "exhaust",
    "exhibit", "exile", "exist", "exit", "exotic", "expand", "expect", "expire", "explain", "expose", "express",
    "extend", "extra", "eye", "eyebrow", "fabric", "face", "faculty", "fade", "faint", "faith", "fall", "false",
    "fame", "family", "famous", "fan", "fancy", "fantasy", "farm", "fashion", "fat", "fatal", "father", "fatigue",
    "fault", "favorite", "feature", "february", "federal", "fee", "feed", "feel", "female", "fence", "festival",
    "fetch", "fever", "few", "fiber", "fiction", "field", "figure", "file", "film", "filter", "final", "find", "fine",
    "finger", "finish", "fire", "firm", "first", "fiscal", "fish", "fit", "fitness", "fix", "flag", "flame", "flash",
    "flat", "flavor", "flee", "flight", "flip", "float", "flock", "floor", "flower", "fluid", "flush", "fly", "foam",
    "focus", "fog", "foil", "fold", "follow", "food", "foot", "force", "forest", "forget", "fork", "fortune", "forum",
    "forward", "fossil", "foster", "found", "fox", "fragile", "frame", "frequent", "fresh", "friend", "fringe", "frog",
    "front", "frost", "frown", "frozen", "fruit", "fuel", "fun", "funny", "furnace", "fury", "future", "gadget", "gain",
    "galaxy", "gallery", "game", "gap", "garage", "garbage", "garden", "garlic", "garment", "gas", "gasp", "gate",
    "gather", "gauge", "gaze", "general", "genius", "genre", "gentle", "genuine", "gesture", "ghost", "giant", "gift",
    "giggle", "ginger", "giraffe", "girl", "give", "glad", "glance", "glare", "glass", "glide", "glimpse", "globe",
    "gloom", "glory", "glove", "glow", "glue", "goat", "goddess", "gold", "good", "goose", "gorilla", "gospel", "gossip",
    "govern", "gown", "grab", "grace", "grain", "grant", "grape", "grass", "gravity", "great", "green", "grid", "grief",
    "grit", "grocery", "group", "grow", "grunt", "guard", "guess", "guide", "guilt", "guitar", "gun", "gym", "habit",
    "hair", "half", "hammer", "hamster", "hand", "happy", "harbor", "hard", "harsh", "harvest", "hat", "have", "hawk",
    "hazard", "head", "health", "heart", "heavy", "hedgehog", "height", "hello", "helmet", "help", "hen", "hero", "hidden",
    "high", "hill", "hint", "hip", "hire", "history", "hobby", "hockey", "hold", "hole", "holiday", "hollow", "home",
    "honey", "hood", "hope", "horn", "horror", "horse", "hospital", "host", "hotel", "hour", "hover", "hub", "huge",
    "human", "humble", "humor", "hundred", "hungry", "hunt", "hurdle", "hurry", "hurt", "husband", "hybrid", "ice",
    "icon", "idea", "identify", "idle", "ignore", "ill", "illegal", "illness", "image", "imitate", "immense", "immune",
    "impact", "impose", "improve", "impulse", "inch", "include", "income", "increase", "index", "indicate", "indoor",
    "industry", "infant", "inflict", "inform", "inhale", "inherit", "initial", "inject", "injury", "inmate", "inner",
    "innocent", "input", "inquiry", "insane", "insect", "inside", "inspire", "install", "intact", "interest", "into",
    "invest", "invite", "involve", "iron", "island", "isolate", "issue", "item", "ivory", "jacket", "jaguar", "jar",
    "jazz", "jealous", "jeans", "jelly", "jewel", "job", "join", "joke", "journey", "joy", "judge", "juice", "jump",
    "jungle", "junior", "junk", "just", "kangaroo", "keen", "keep", "ketchup", "key", "kick", "kid", "kidney", "kind",
    "kingdom", "kiss", "kit", "kitchen", "kite", "kitten", "kiwi", "knee", "knife", "knock", "know", "lab", "label",
    "labor", "ladder", "lady", "lake", "lamp", "language", "laptop", "large", "later", "latin", "laugh", "laundry",
    "lava", "law", "lawn", "lawsuit", "layer", "lazy", "leader", "leaf", "learn", "leave", "lecture", "left", "leg",
    "legal", "legend", "leisure", "lemon", "lend", "length", "lens", "leopard", "lesson", "letter", "level", "liar",
    "liberty", "library", "license", "life", "lift", "light", "like", "limb", "limit", "link", "lion", "liquid",
    "list", "little", "live", "lizard", "load", "loan", "lobster", "local", "lock", "logic", "lonely", "long", "loop",
    "lottery", "loud", "lounge", "love", "loyal", "lucky", "luggage", "lumber", "lunar", "lunch", "luxury", "lyrics",
    "machine", "mad", "magic", "magnet", "maid", "mail", "main", "major", "make", "mammal", "man", "manage", "mandate",
    "mango", "mansion", "manual", "maple", "marble", "march", "margin", "marine", "market", "marriage", "mask", "mass",
    "master", "match", "material", "math", "matrix", "matter", "maximum", "maze", "meadow", "mean", "measure", "meat",
    "mechanic", "medal", "media", "melody", "melt", "member", "memory", "mention", "menu", "mercy", "merge", "merit",
    "merry", "mesh", "message", "metal", "method", "middle", "midnight", "milk", "million", "mimic", "mind", "minimum",
    "minor", "minute", "miracle", "mirror", "misery", "miss", "mistake", "mix", "mixed", "mixture", "mobile", "model",
    "modify", "mom", "moment", "monitor", "monkey", "monster", "month", "moon", "moral", "more", "morning", "mosquito",
    "mother", "motion", "motor", "mountain", "mouse", "move", "movie", "much", "muffin", "mule", "multiply", "muscle",
    "museum", "mushroom", "music", "must", "mutual", "myself", "mystery", "myth", "naive", "name", "napkin", "narrow",
    "nasty", "nation", "nature", "near", "neck", "need", "negative", "neglect", "neither", "nephew", "nerve", "nest",
    "net", "network", "neutral", "never", "news", "next", "nice", "night", "noble", "noise", "nominee", "noodle",
    "normal", "north", "nose", "notable", "note", "nothing", "notice", "novel", "now", "nuclear", "number", "nurse",
    "nut", "oak", "obey", "object", "oblige", "obscure", "observe", "obtain", "obvious", "occur", "ocean", "october",
    "odor", "off", "offer", "office", "often", "oil", "okay", "old", "olive", "olympic", "omit", "once", "one",
    "onion", "online", "only", "open", "opera", "opinion", "oppose", "option", "orange", "orbit", "orchard", "order",
    "ordinary", "organ", "orient", "original", "orphan", "ostrich", "other", "outdoor", "outer", "output", "outside",
    "oval", "oven", "over", "own", "owner", "oxygen", "oyster", "ozone", "pact", "paddle", "page", "pair", "palace",
    "palm", "panda", "panel", "panic", "panther", "paper", "parade", "parent", "park", "parrot", "party", "pass",
    "patch", "path", "patient", "patrol", "pattern", "pause", "pave", "payment", "peace", "peanut", "pear", "peasant",
    "pelican", "pen", "penalty", "pencil", "people", "pepper", "perfect", "permit", "person", "pet", "phone", "photo",
    "phrase", "physical", "piano", "picnic", "picture", "piece", "pig", "pigeon", "pill", "pilot", "pink", "pioneer",
    "pipe", "pistol", "pitch", "pizza", "place", "planet", "plastic", "plate", "play", "please", "pledge", "pluck",
    "plug", "plunge", "poem", "poet", "point", "polar", "pole", "police", "pond", "pony", "pool", "popular", "portion",
    "position", "possible", "post", "potato", "pottery", "poverty", "powder", "power", "practice", "praise", "predict",
    "prefer", "prepare", "present", "pretty", "prevent", "price", "pride", "primary", "print", "priority", "prison",
    "private", "prize", "problem", "process", "produce", "profit", "program", "project", "promote", "proof", "property",
    "prosper", "protect", "proud", "provide", "public", "pudding", "pull", "pulp", "pulse", "pumpkin", "punch", "pupil",
    "puppy", "purchase", "purity", "purpose", "purse", "push", "put", "puzzle", "pyramid", "quality", "quantum",
    "quarter", "question", "quick", "quit", "quiz", "quote", "rabbit", "raccoon", "race", "rack", "radar", "radio",
    "rail", "rain", "raise", "rally", "ramp", "ranch", "random", "range", "rapid", "rare", "rate", "rather", "raven",
    "raw", "razor", "ready", "real", "reason", "rebel", "rebuild", "recall", "receive", "recipe", "record", "recycle",
    "reduce", "reflect", "reform", "refuse", "region", "regret", "regular", "reject", "relax", "release", "relief",
    "rely", "remain", "remember", "remind", "remove", "render", "renew", "rent", "reopen", "repair", "repeat", "replace",
    "report", "require", "rescue", "resemble", "resist", "resource", "response", "result", "retire", "retreat", "return",
    "reunion", "reveal", "review", "reward", "rhythm", "rib", "ribbon", "rice", "rich", "ride", "ridge", "rifle", "right",
    "rigid", "ring", "riot", "ripple", "risk", "ritual", "rival", "river", "road", "roast", "robot", "robust", "rocket",
    "romance", "roof", "rookie", "room", "rose", "rotate", "rough", "round", "route", "royal", "rubber", "rude", "rug",
    "rule", "run", "runway", "rural", "sad", "saddle", "sadness", "safe", "sail", "salad", "salmon", "salon", "salt",
    "salute", "same", "sample", "sand", "satisfy", "satoshi", "sauce", "sausage", "save", "say", "scale", "scan",
    "scare", "scatter", "scene", "scheme", "school", "science", "scissors", "scorpion", "scout", "scrap", "screen",
    "script", "scrub", "sea", "search", "season", "seat", "second", "secret", "section", "security", "seed", "seek",
    "segment", "select", "sell", "seminar", "senior", "sense", "sentence", "series", "service", "session", "settle",
    "setup", "seven", "shadow", "shaft", "shallow", "share", "shed", "shell", "sheriff", "shield", "shift", "shine",
    "ship", "shiver", "shock", "shoe", "shoot", "shop", "short", "shoulder", "shove", "shrimp", "shrug", "shuffle",
    "shy", "sibling", "sick", "side", "siege", "sight", "sign", "silent", "silk", "silly", "silver", "similar", "simple",
    "since", "sing", "siren", "sister", "situate", "six", "size", "skate", "sketch", "ski", "skill", "skin", "skirt",
    "skull", "slab", "slam", "sleep", "slender", "slice", "slide", "slight", "slim", "slogan", "slot", "slow", "slush",
    "small", "smart", "smile", "smoke", "smooth", "snack", "snake", "snap", "sniff", "snow", "soap", "soccer", "social",
    "sock", "soda", "soft", "solar", "soldier", "solid", "solution", "solve", "someone", "song", "soon", "sorry",
    "sort", "soul", "sound", "soup", "source", "south", "space", "spare", "spatial", "spawn", "speak", "special",
    "speed", "spell", "spend", "sphere", "spice", "spider", "spike", "spin", "spirit", "split", "spoil", "sponsor",
    "spoon", "sport", "spot", "spray", "spread", "spring", "spy", "square", "squeeze", "squirrel", "stable", "stadium",
    "staff", "stage", "stairs", "stamp", "stand", "start", "state", "stay", "steak", "steel", "stem", "step", "stereo",
    "stick", "still", "sting", "stock", "stomach", "stone", "stool", "story", "stove", "strategy", "street", "strike",
    "strong", "struggle", "student", "stuff", "stumble", "style", "subject", "submit", "subway", "success", "such",
    "sudden", "suffer", "sugar", "suggest", "suit", "summer", "sun", "sunny", "sunset", "super", "supply", "supreme",
    "sure", "surface", "surge", "surprise", "surround", "survey", "suspect", "sustain", "swallow", "swamp", "swap",
    "swarm", "swear", "sweet", "swift", "swim", "swing", "switch", "sword", "symbol", "symptom", "syrup", "system",
    "table", "tackle", "tag", "tail", "talent", "talk", "tank", "tape", "target", "task", "taste", "tattoo", "taxi",
    "teach", "team", "tell", "ten", "tenant", "tennis", "tent", "term", "test", "text", "thank", "that", "theme", "then",
    "theory", "there", "they", "thing", "this", "thought", "three", "thrive", "throw", "thumb", "thunder", "ticket",
    "tide", "tiger", "tilt", "timber", "time", "tiny", "tip", "tired", "tissue", "title", "toast", "tobacco", "today",
    "toddler", "toe", "together", "toilet", "token", "tomato", "tomorrow", "tone", "tongue", "tonight", "tool", "tooth",
    "top", "topic", "topple", "torch", "tornado", "tortoise", "toss", "total", "tourist", "toward", "tower", "town",
    "toy", "track", "trade", "traffic", "tragic", "train", "transfer", "trap", "trash", "travel", "tray", "treat",
    "tree", "trend", "trial", "tribe", "trick", "trigger", "trim", "trip", "trophy", "trouble", "truck", "true",
    "truly", "trumpet", "trust", "truth", "try", "tube", "tuition", "tumble", "tuna", "tunnel", "turkey", "turn",
    "turtle", "twelve", "twenty", "twice", "twin", "twist", "two", "type", "typical", "ugly", "umbrella", "unable",
    "unaware", "uncle", "uncover", "under", "undo", "unfair", "unfold", "unhappy", "uniform", "unique", "unit",
    "universe", "unknown", "unlock", "until", "unusual", "unveil", "update", "upgrade", "uphold", "upon", "upper",
    "upset", "urban", "urge", "usage", "use", "used", "useful", "useless", "usual", "utility", "vacant", "vacuum",
    "vague", "valid", "valley", "valve", "van", "vanish", "vapor", "various", "vast", "vault", "vehicle", "velvet",
    "vendor", "venture", "venue", "verb", "verify", "version", "very", "vessel", "veteran", "viable", "vibrant",
    "vicious", "victory", "video", "view", "village", "vintage", "violin", "virtual", "virus", "visa", "visit",
    "visual", "vital", "vivid", "vocal", "voice", "void", "volcano", "volume", "vote", "voyage", "wage", "wagon",
    "wait", "walk", "wall", "walnut", "want", "warfare", "warm", "warrior", "wash", "wasp", "waste", "water", "wave",
    "way", "wealth", "weapon", "wear", "weasel", "weather", "web", "wedding", "weekend", "weird", "welcome", "west",
    "wet", "whale", "what", "wheat", "wheel", "when", "where", "whip", "whisper", "wide", "width", "wife", "wild",
    "will", "win", "window", "wine", "wing", "wink", "winner", "winter", "wire", "wisdom", "wise", "wish", "witness",
    "wolf", "woman", "wonder", "wood", "wool", "word", "work", "world", "worry", "worth", "wrap", "wreck", "wrestle",
    "wrist", "write", "wrong", "yard", "year", "yellow", "you", "young", "youth", "zebra", "zero", "zone", "zoo"
};

static std::array<guint8, 32> authSecret(std::string_view connectionSecret, std::string_view userSecret) {
    std::array<guint8, 32> ret;
    if (g_checksum_type_get_length(G_CHECKSUM_SHA256) != ret.size()) {
        fatal("checksum setup bogus");
    }
    auto checksummer = g_checksum_new(G_CHECKSUM_SHA256);
    if (!checksummer) fatal("g_checksum_new failed");
    g_checksum_update(checksummer, (const guchar*)connectionSecret.data(), connectionSecret.size());
    g_checksum_update(checksummer, (const guchar*)userSecret.data(), userSecret.size());
    g_checksum_update(checksummer, (const guchar*)"CONNAUTH", 8);
    gsize s = ret.size();
    g_checksum_get_digest(checksummer, (guint8*)ret.begin(), &s);
    if (s != ret.size()) {
        fatal("checksum get_digest bogus");
    }
    g_checksum_free(checksummer);
    return ret;
}

static int timer_generation = 0;
static int onQuicPollTimeout(void *data) {
    if (timer_generation == (intptr_t)data) {
         quicPoll();
    }

    return false;
}

static int keepAliveTimer(void *data) {
    (void)data;
    //SSL_write(quicKeepaliveStream, "*", 1);
    //quicPoll();
    return true;
}

static void sendAuthFrame(unsigned char *bufPtr, int bufLen) {
    char c;
    c = (bufLen >> 8) & 0xff;
    int written = SSL_write(quicAuthStream, &c, 1);
    if (written != 1) {
        fatal_ossl("sendAuthFrame failed writeA: {}\n", written);
    }
    c = bufLen & 0xff;
    written = SSL_write(quicAuthStream, &c, 1);
    if (written != 1) {
        fatal_ossl("sendAuthFrame failed writeB: {}\n", written);
    }
    written = SSL_write(quicAuthStream, bufPtr, bufLen);
    if (written != bufLen) {
        fatal_ossl("sendAuthFrame failed writeC: {}\n", written);
    }
}


static std::unique_ptr<ModeBase> mode;

static SoupSession *soupSession = nullptr;
static NiceAgent *iceAgent = nullptr;

static void onIceCandidateGatheringDone(NiceAgent *iceAgent, guint stream_id, gpointer data);
static void onIceReceive(NiceAgent *iceAgent, guint streamId, guint componentId, guint len, gchar *buf, gpointer data);
static void onIceComponentStateChanged(NiceAgent *iceAgent, guint streamId, guint componentId, guint state, gpointer data);

static void sendRendMessage(SoupWebsocketConnection *wsConnection, nlohmann::json msg) {
    std::string out = msg.dump();
    log(LOG_REND, "Sending: {}\n", out);
    soup_websocket_connection_send_text(wsConnection, out.data());
}

static void sendBind(SoupWebsocketConnection *wsConnection, std::string_view side) {
    nlohmann::json msg;
    msg["type"] = "bind";
    msg["appid"] = appId;
    msg["side"] = side;
    msg["client_version"] = nlohmann::json{clientVersion1, clientVersion2};
    sendRendMessage(wsConnection, msg);
}

static void sendICE(SoupWebsocketConnection *wsConnection, int streamId) {
    nlohmann::json ice;

    gchar *user = NULL;
    gchar *password = NULL;
    if (!nice_agent_get_local_credentials(iceAgent, streamId, &user, &password)) {
        // TODO error handling
        fatal("nice_agent_get_local_credentials");
    }

    ice["u"] = user;
    ice["p"] = password;

    std::vector<nlohmann::json> candidatesJson;

    auto candidates = nice_agent_get_local_candidates(iceAgent, streamId, 1);
    if (candidates == NULL) {
        // TODO error handling
        fatal("no candidates");
    }

    for (auto item = candidates; item; item = item->next) {
        NiceCandidate *candidate = (NiceCandidate *)item->data;

        nlohmann::json candJson;

        gchar ipString[INET6_ADDRSTRLEN];
        nice_address_to_string (&candidate->addr, ipString);

        candJson["f"] = candidate->foundation;
        candJson["a"] = ipString;
        candJson["p"] = nice_address_get_port(&candidate->addr);
        candJson["tr"] = candidate->transport;
        candJson["l"] = candidate->priority;
        candJson["t"] = candidate->type;

        if (nice_address_is_valid(&candidate->base_addr) &&
            !nice_address_equal(&candidate->addr, &candidate->base_addr)) {
            nice_address_to_string (&candidate->base_addr, ipString);
            candJson["ba"] = ipString;
            candJson["bp"] = nice_address_get_port(&candidate->base_addr);
        }

        candidatesJson.push_back(candJson);
    }

    ice["c"] = candidatesJson;

    sendRendMessage(wsConnection, {
                    {"type", "add"},
                    {"phase", "ice"},
                    {"body", ice.dump()}
                });
}

static void applyRemoteICE(nlohmann::json msg, int streamId) {
    std::string body = msg.value("body", "");
    auto ice = nlohmann::json::parse(body);
    GSList *candidates = nullptr;

    std::string user = ice["u"];
    std::string password = ice["p"];

    std::vector<nlohmann::json> candidatesJson = ice["c"];

    for (nlohmann::json candJson : candidatesJson) {
        NiceCandidate *candidate = nice_candidate_new(candJson["t"]);
        candidate->component_id = 1;
        candidate->stream_id = streamId;
        candidate->transport = candJson["tr"];
        std::string foundation = candJson["f"];
        g_strlcpy(candidate->foundation, foundation.data(), NICE_CANDIDATE_MAX_FOUNDATION);
        candidate->priority = candJson["l"];
        std::string addr = candJson["a"];
        if (!nice_address_set_from_string (&candidate->addr, addr.data())) {
          nice_candidate_free (candidate);
          // TODO error handling
          continue;
        }
        nice_address_set_port (&candidate->addr, candJson["p"]);

        std::string base_addr = candJson.value("ba", "");
        if (base_addr.size()) {
          if (!nice_address_set_from_string (&candidate->base_addr, base_addr.data())) {
            nice_candidate_free (candidate);
            // TODO error handling
            continue;
          }
          nice_address_set_port (&candidate->base_addr, candJson["bp"]);
        }

        candidates = g_slist_prepend (candidates, candidate);
    }

    nice_agent_set_remote_credentials(iceAgent, streamId, user.data(), password.data());
    nice_agent_set_remote_candidates(iceAgent, streamId, 1, candidates);
}


struct RoleInitiator {
    RoleInitiator(PeersockConfig config) : config(config) {};

    PeersockConfig config;
    SoupWebsocketConnection *wsConnection;
    std::string nameplate;
    std::string code;
    std::string localSide = "initiator";
    std::array<guint8, 32> auth;
    bool authDone = false;

    void handleWsData(nlohmann::json data) {
        state = std::visit([&](auto &state) -> State {
            return (*this)(state, data);
        }, state);
    }

    void handleIceGatheringDone() {
        state = std::visit([&](auto &state) -> State {
            return onLocalCandidates(state);
        }, state);
    }

    void handleQuicConnected(std::string_view tlsExport) {
        // other side starts management streams, nothing to do here
        auth = authSecret(tlsExport, code);
    }

    int handleQuicStreamOpened(SSL *stream) {
        int stream_id = SSL_get_stream_id(stream);
        log(LOG_QUIC, "Got new stream {}\n", stream_id);
        if (stream_id == 0) { // keep alive stream
            quicKeepaliveStream = stream;
        } else if (stream_id == 4) { // auth stream
            quicAuthStream = stream;
        } else if (authDone) {
            if (!mode) {
                fatal("Bad mode\n");
            } else {
                mode->handleQuicStreamOpened(stream);
            }
        } else {
            fatal("unexpected stream before auth: {}\n", stream_id);
        }
        return 0;
    }

    void quicPoll() {
        char buf[1000];
        int read;

        if (quicKeepaliveStream) {
            read = quicReadOrDie(quicKeepaliveStream, buf, sizeof(buf));
            if (read > 0) {
                log(LOG_QUIC, "quic read on keepalive: l{}:{}\n", read, std::string_view{(const char*)buf, (uint)read});
            }
        }

        if (quicAuthStream && !authDone) {
            //log(LOG_QUIC, "quic read on auth: l{}:{}\n", read, std::string_view{(const char*)buf, (uint)read});
            quicReadFramedMessageOrDie(quicAuthStream, AuthStreamBuffer, [&] (uint8_t *frame, ssize_t frameLen) {
                log(LOG_AUTH, "Auth step {}\n", authStep);
                if (authStep == 0) {
                    ++authStep;
                    log(LOG_AUTH, "SM msg1: {}/{}\n", frameLen, g_base64_encode(frame, frameLen));

                    if (otrl_sm_step2a(&authState, frame, frameLen, 0) != gcry_error(GPG_ERR_NO_ERROR)) {
                        fatal("otrl_sm_step2a failed\n");
                    }
                    unsigned char *bufPtr = nullptr;
                    int bufLen = 0;
                    if (otrl_sm_step2b(&authState, auth.data(), auth.size(), &bufPtr, &bufLen) != gcry_error(GPG_ERR_NO_ERROR)) {
                        fatal("otrl_sm_step2b failed\n");
                        exit(1);
                    }
                    sendAuthFrame(bufPtr, bufLen);
                    log(LOG_AUTH, "SM msg2: {}/{}\n", bufLen, g_base64_encode(bufPtr, bufLen));

                    free(bufPtr);
                } else if (authStep == 1) {
                    ++authStep;
                    log(LOG_AUTH, "SM msg3: {}/{}\n", frameLen, g_base64_encode(frame, frameLen));

                    unsigned char *buf1Ptr = nullptr;
                    int buf1Len = 0;
                    auto res = otrl_sm_step4(&authState, frame, frameLen, &buf1Ptr, &buf1Len);
                    if (res != gcry_error(GPG_ERR_NO_ERROR)) {
                        if (res == gcry_error(GPG_ERR_INV_VALUE)) {
                                fatal("connection code mismatch");
                        }
                        fatal("otrl_sm_step4 failed\n");
                    }
                    sendAuthFrame(buf1Ptr, buf1Len);
                    log(LOG_AUTH, "SM msg4: {}/{}\n", buf1Len, g_base64_encode(buf1Ptr, buf1Len));
                    free(buf1Ptr);
                    writeUserMessage({
                                         {"event", "auth-success"},
                                     },
                                     "Auth success\n");
                    authDone = true;
                    if (!mode) {
                        fatal("Bad mode\n");
                    } else {
                        mode->connectionMade(::quicPoll, new RemoteConnectionImpl(quic_connection));
                    }
                }
            });
        }

        if (authDone) {
            if (!mode) {
                fatal("Bad mode\n");
            } else {
                mode->quicPoll();
            }
        }
    }

    struct Init {};
    struct WaitingForNameplace {};
    struct WaitingForClaim {};
    struct WaitingForRemoteICECandidates {};
    struct WaitingForLocalCandidates { nlohmann::json remoteCandidates; unsigned streamId; };

    using State = std::variant<Init, WaitingForNameplace, WaitingForClaim,
                               WaitingForRemoteICECandidates, WaitingForLocalCandidates>;
    State state = Init{};

    State operator()(Init, nlohmann::json data) {
        std::string type = data.value("type", "");

        if (type == "welcome"s) {
            // TODO handle motd and co

            sendBind(wsConnection, localSide);
            sendRendMessage(wsConnection, {
                            {"type", "allocate"}
                        });
            return WaitingForNameplace{};
        } else if (type == "ack"s) {
            // ignore
        } else {
            log(LOG_REND, "Unimplemented server message: {}\n", type);
        }

        return state;
    }

    State operator()(WaitingForNameplace, nlohmann::json data) {
        std::string type = data.value("type", "");

        if (type == "allocated"s) {
            nameplate = data.value("nameplate", "");
            std::random_device rnd;
            std::uniform_int_distribution dist(0, 2048);
            code = fmt::format("{}-{}-{}-{}", nameplate,
                               words[dist(rnd)], words[dist(rnd)], words[dist(rnd)], words[dist(rnd)]);
            codeCallback(code);

            sendRendMessage(wsConnection, {
                            {"type", "claim"},
                            {"nameplate", nameplate}
                        });

            return WaitingForClaim{};
        } else if (type == "ack"s) {
            // ignore
        } else {
            log(LOG_REND, "Unimplemented server message: {}\n", type);
        }

        return state;
    }

    State operator()(WaitingForClaim, nlohmann::json data) {
        std::string type = data.value("type", "");

        if (type == "claimed"s) {
            std::string mailbox = data.value("mailbox", "");

            sendRendMessage(wsConnection, {
                            {"type", "open"},
                            {"mailbox", mailbox}
                        });

            return WaitingForRemoteICECandidates{};
        } else if (type == "ack"s) {
            // ignore
        } else {
            log(LOG_REND, "Unimplemented server message: {}\n", type);
        }

        return state;
    }

    State operator()(WaitingForRemoteICECandidates, nlohmann::json data) {
        std::string type = data.value("type", "");

        if (type == "message"s) {
            std::string side = data.value("side", "");
            if (side != localSide) {
                log(LOG_REND, "Got remote message: {}\n", data.value("body", ""));
                if (data.value("phase", "") == "ice"s) {
                    iceAgent = nice_agent_new(g_main_context_get_thread_default() /*g_main_loop_get_context (mainLoop)*/, NICE_COMPATIBILITY_RFC5245);
                    if (!iceAgent) {
                        fatal("Could not allocate ice agent\n");
                    }

                    g_object_set(G_OBJECT(iceAgent), "stun-server", config.stunServer.data(), NULL);
                    g_object_set(G_OBJECT(iceAgent), "stun-server-port", config.stunPort, NULL);

                    gboolean controlling = true;
                    g_object_set(iceAgent, "controlling-mode", controlling, NULL);
                    g_signal_connect(iceAgent, "candidate-gathering-done", G_CALLBACK(onIceCandidateGatheringDone), NULL);
                    g_signal_connect(iceAgent, "component-state-changed", G_CALLBACK(onIceComponentStateChanged), NULL);

                    guint streamId = nice_agent_add_stream(iceAgent, 1);
                    if (!streamId) {
                        fatal("Invalid zero stream id\n");
                    }

                    nice_agent_attach_recv(iceAgent, streamId, 1, g_main_context_get_thread_default() /*g_main_loop_get_context (mainLoop)*/, onIceReceive, NULL);

                    if (!nice_agent_gather_candidates(iceAgent, streamId)) {
                        fatal("nice_agent_gather_candidates failed.\n");
                    }

                    return WaitingForLocalCandidates{data, streamId};
                }
            }
        } else if (type == "ack"s) {
            // ignore
        } else {
            log(LOG_REND, "Unimplemented server message: {}\n", type);
        }

        return state;
    }

    State onLocalCandidates(WaitingForLocalCandidates& s) {
        applyRemoteICE(s.remoteCandidates, s.streamId);

        sendICE(wsConnection, s.streamId);
        return s;
    }

    template<typename AnyState>
    State operator()(AnyState s, nlohmann::json data) {
        std::string type = data.value("type", "");
        if (type != "ack" && type != "message") {
            log(LOG_REND, "Websocket message in unexpected state\n");
        }
        return s;
    }

    template<typename AnyState>
    State onLocalCandidates(AnyState s) {
        log(LOG_ICE, "Local candidates in unexpected state\n");
        return s;
    }
};

struct RoleFromCode {
    std::string code;
    PeersockConfig config;
    SoupWebsocketConnection *wsConnection;
    std::string localSide = "code";
    bool authDone = false;

    void handleWsData(nlohmann::json data) {
        state = std::visit([&](auto &state) -> State {
            return onWsData(state, data);
        }, state);
    }

    void handleIceGatheringDone() {
        state = std::visit([&](auto &state) -> State {
            return onLocalCandidates(state);
        }, state);
    }
    void handleQuicConnected(std::string_view tlsExport) {
        auto auth = authSecret(tlsExport, code);
        quicKeepaliveStream = SSL_new_stream(quic_client, 0);
        g_timeout_add(15000, keepAliveTimer, nullptr);
        quicAuthStream = SSL_new_stream(quic_client, 0);
        unsigned char *bufPtr = nullptr;
        int bufLen = 0;
        if (otrl_sm_step1(&authState, auth.data(), auth.size(), &bufPtr, &bufLen) != gcry_error(GPG_ERR_NO_ERROR)) {
            fatal("otrl_sm_step1 failed\n");
        }
        sendAuthFrame(bufPtr, bufLen);
        log(LOG_AUTH, "SM msg1: {}/{}\n", bufLen, g_base64_encode(bufPtr, bufLen));
    }

    int handleQuicStreamOpened(SSL *stream) {
        int stream_id = SSL_get_stream_id(stream);
        log(LOG_QUIC, "Got new stream {}\n", stream_id);
        if (authDone) {
            if (!mode) {
                fatal("Bad mode\n");
            } else {
                mode->handleQuicStreamOpened(stream);
            }
        } else {
            fatal("unexpected stream before auth: {}\n", stream_id);
        }
        return 0;
    }

    void quicPoll() {
        if (quicAuthStream && !authDone) {
            quicReadFramedMessageOrDie(quicAuthStream, AuthStreamBuffer, [&] (uint8_t *frame, ssize_t frameLen) {
                log(LOG_QUIC, "quic auth stream data l{} bytes\n", frameLen);
                log(LOG_AUTH, "Auth step {}\n", authStep);
                if (authStep == 0) {
                    ++authStep;
                    log(LOG_AUTH, "SM msg2: {}/{}\n", frameLen, g_base64_encode(frame, frameLen));
                    unsigned char *buf2Ptr = nullptr;
                    int buf2Len = 0;
                    if (otrl_sm_step3(&authState, frame, frameLen, &buf2Ptr, &buf2Len) != gcry_error(GPG_ERR_NO_ERROR)) {
                        fatal("otrl_sm_step3 failed\n");
                    }
                    sendAuthFrame(buf2Ptr, buf2Len);
                    log(LOG_AUTH, "SM msg3: {}/{}\n", buf2Len, g_base64_encode(buf2Ptr, buf2Len));
                    log(LOG_AUTH, "sending auth len:{}\n", buf2Len);
                    free(buf2Ptr);
                } else if (authStep == 1) {
                    ++authStep;
                    log(LOG_AUTH, "SM msg4: {}/{}\n", frameLen, g_base64_encode(frame, frameLen));
                    unsigned int ret = otrl_sm_step5(&authState, frame, frameLen);
                    if (ret != gcry_error(GPG_ERR_NO_ERROR)) {
                        fatal("otrl_sm_step5 failed: {:x}\n", ret);
                        exit(1);
                    }
                    writeUserMessage({
                                         {"event", "auth-success"},
                                     },
                                     "Auth success\n");
                    authDone = true;
                    if (!mode) {
                        fatal("Bad mode\n");
                    } else {
                        mode->connectionMade(::quicPoll, new RemoteConnectionImpl(quic_client));
                    }
                }
            });

        }

        if (authDone) {
            if (!mode) {
                fatal("Bad mode\n");
            } else {
                mode->quicPoll();
            }
        }
    }

    struct Init {};
    struct WaitingForClaim {};
    struct WaitingForLocalCandidates { std::string mailbox; unsigned streamId; };
    struct WaitingForRemoteICECandidates { std::string mailbox; unsigned streamId; };

    using State = std::variant<Init, WaitingForClaim, WaitingForLocalCandidates, WaitingForRemoteICECandidates>;
    State state = Init{};

    State onWsData(Init, nlohmann::json data) {
        std::string type = data.value("type", "");

        if (type == "welcome"s) {
            // TODO handle motd and co
            sendBind(wsConnection, localSide);

            std::string nameplate = code.substr(0, code.find_first_of('-'));

            sendRendMessage(wsConnection, {
                            {"type", "claim"},
                            {"nameplate", nameplate}
                        });

            return WaitingForClaim{};
        } else if (type == "ack"s) {
            // ignore
        } else {
            log(LOG_REND, "Unimplemented server message: {}\n", type);
        }

        return state;
    }

    State onWsData(WaitingForClaim, nlohmann::json data) {
        std::string type = data.value("type", "");

        if (type == "claimed"s) {
            std::string mailbox = data.value("mailbox", "");

            iceAgent = nice_agent_new(g_main_context_get_thread_default() /*g_main_loop_get_context (mainLoop)*/, NICE_COMPATIBILITY_RFC5245);
            if (!iceAgent) {
                fatal("Could not allocate ice agent\n");
            }

            g_object_set(G_OBJECT(iceAgent), "stun-server", config.stunServer.data(), NULL);
            g_object_set(G_OBJECT(iceAgent), "stun-server-port", config.stunPort, NULL);

            gboolean controlling = false;
            g_object_set(iceAgent, "controlling-mode", controlling, NULL);
            g_signal_connect(iceAgent, "candidate-gathering-done", G_CALLBACK(onIceCandidateGatheringDone), NULL);
            g_signal_connect(iceAgent, "component-state-changed", G_CALLBACK(onIceComponentStateChanged), NULL);

            guint streamId = nice_agent_add_stream(iceAgent, 1);
            if (!streamId) {
                fatal("Invalid zero stream id\n");
            }

            nice_agent_attach_recv(iceAgent, streamId, 1, g_main_context_get_thread_default() /*g_main_loop_get_context (mainLoop)*/, onIceReceive, NULL);

            if (!nice_agent_gather_candidates(iceAgent, streamId)) {
                fatal("nice_agent_gather_candidates failed.\n");
            }

            return WaitingForLocalCandidates{mailbox, streamId};
        } else if (type == "ack"s) {
            // ignore
        } else {
            log(LOG_REND, "Unimplemented server message: {}\n", type);
        }

        return state;
    }

    State onLocalCandidates(WaitingForLocalCandidates& s) {
        sendRendMessage(wsConnection, {
                        {"type", "open"},
                        {"mailbox", s.mailbox}
                    });

        sendICE(wsConnection, s.streamId);

        return WaitingForRemoteICECandidates{s.mailbox, s.streamId};
    }


    State onWsData(WaitingForRemoteICECandidates s, nlohmann::json data) {
        std::string type = data.value("type", "");

        if (type == "message"s) {
            std::string side = data.value("side", "");
            if (side != localSide) {
                log(LOG_REND, "Got remote message: {}\n", data.value("body", ""));
                if (data.value("phase", "") == "ice"s) {
                    applyRemoteICE(data, s.streamId);
                }
            }
        } else if (type == "ack"s) {
            // ignore
        } else {
            log(LOG_REND, "Unimplemented server message: {}\n", type);
        }

        return state;
    }

    template<typename AnyState>
    State onWsData(AnyState s, nlohmann::json data) {
        std::string type = data.value("type", "");
        if (type != "ack") {
            log(LOG_REND, "Websocket message in unexpected state\n");
        }
        return s;
    }

    template<typename AnyState>
    State onLocalCandidates(AnyState s) {
        log(LOG_REND, "Local candidates in unexpected state\n");
        return s;
    }

};

static std::variant<std::monostate, RoleInitiator, RoleFromCode> role;

static void onRendMessage(SoupWebsocketConnection *conn, gint type, GBytes *message, gpointer data) {
    (void)conn; (void)data;
    if (type == SOUP_WEBSOCKET_DATA_TEXT) {
        gsize sz;
        const void *ptr;

        ptr = g_bytes_get_data(message, &sz);
        log(LOG_REND, "Received text data: {}\n", (const char*)ptr);

        auto j = nlohmann::json::parse(std::string_view((const char*)ptr));
        std::visit([&] (auto &role) {
            if constexpr (std::is_same_v<typeof(role), std::monostate>) {
                fatal("Bad role\n");
            } else {
                role.handleWsData(j);
            }
        }, role);
    }
}


static void onIceComponentStateChanged(NiceAgent *agent, guint streamId, guint componentId, guint state, gpointer data) {
    static const gchar *state_name[] = {"disconnected", "gathering", "connecting",
                                        "connected", "ready", "failed"};

    log(LOG_ICE, "State change: {}\n", state_name[state]);
    if (state == NICE_COMPONENT_STATE_CONNECTED) {
        if (std::holds_alternative<RoleFromCode>(role)) {
            SSL_CTX_set_verify(quic_ssl_ctx, SSL_VERIFY_PEER, NULL);
            quic_client = SSL_new(quic_ssl_ctx);
            if (!quic_client) {
                fatal_ossl("SSL_new failed:\n");
            }
            BIO *dgram_for_ossl = nullptr;
            if (!BIO_new_bio_dgram_pair(&quic_dgram_bio, 1024 * 1024, &dgram_for_ossl, 1024 * 1024)) {
                fatal_ossl("BIO_new_bio_dgram_pair failed:\n");
            }
            BIO_dgram_set_caps(dgram_for_ossl, BIO_DGRAM_CAP_HANDLES_DST_ADDR);
            BIO_dgram_set_caps(quic_dgram_bio, BIO_DGRAM_CAP_HANDLES_DST_ADDR);

            // TODO possibly add capabilities?

            SSL_set_bio(quic_client, dgram_for_ossl, dgram_for_ossl);

            if (!SSL_set_tlsext_host_name(quic_client, "dummy")) {
                fatal_ossl("SSL_set_tlsext_host_name failed:\n");
            }

            if (!SSL_set1_host(quic_client, "dummy")) {
                fatal_ossl("SSL_set1_host failed:\n");
            }

            if (SSL_set_alpn_protos(quic_client, alpn, sizeof(alpn)) != 0) {
                fatal_ossl("SSL_set_alpn_protos failed:\n");
            }

            BIO_ADDR *peer_addr = BIO_ADDR_new();
            struct in_addr sin_addr = { 0x02020202 };
            BIO_ADDR_rawmake(peer_addr, AF_INET, &sin_addr, sizeof(sin_addr), htons(2020));

            if (!SSL_set1_initial_peer_addr(quic_client, peer_addr)) {
                fatal_ossl("SSL_set1_initial_peer_addr failed:\n");
            }

            if (!SSL_set_blocking_mode(quic_client, 0)) {
                fatal_ossl("SSL_set_blocking_mode failed:\n");
            }

            int ret = SSL_connect(quic_client);
            if (ret >= 0) {
                fatal_ossl("SSL_connect implausible return: {}\n", ret);
            }
            int ssl_error = SSL_get_error(quic_client, ret);
            if (ssl_error != SSL_ERROR_WANT_READ && ssl_error != SSL_ERROR_WANT_WRITE) {
                fatal_ossl("SSL_connect failed\n");
            }
            quic_poll = quic_client;
            iceStreamId = streamId;
            quicPoll();
        }
    }
}


static void OnRendClose(SoupWebsocketConnection *conn, gpointer data) {
    soup_websocket_connection_close(conn, SOUP_WEBSOCKET_CLOSE_NORMAL, nullptr);
    writeUserMessage({
                         {"event", "error"},
                         {"message", "WebSocket connection closed"},
                     },
                     "WebSocket connection closed\n");
}

static void OnRendConnection(SoupSession *session, GAsyncResult *res, gpointer data) {
    log(LOG_FWD, "OnRendConnection\n");
    GError *error = nullptr;
    SoupWebsocketConnection *conn = soup_session_websocket_connect_finish(session, res, &error);
    if (error) {
        fatal("Error: {}\n", error->message);
        g_error_free(error);
        return;
    }

    g_signal_connect(conn, "message", G_CALLBACK(onRendMessage), nullptr);
    g_signal_connect(conn, "closed",  G_CALLBACK(OnRendClose), nullptr);

    std::visit([&] (auto &role) {
        if constexpr (std::is_same_v<typeof(role), std::monostate>) {
            fatal("Bad role\n");
        } else {
            role.wsConnection = conn;
        }
    }, role);
}

static void onIceCandidateGatheringDone(NiceAgent *agent, guint stream_id, gpointer data) {
    log(LOG_ICE, "Gathering done\n");
    std::visit([&] (auto &role) {
        if constexpr (std::is_same_v<typeof(role), std::monostate>) {
            fatal("Bad role\n");
        } else {
            role.handleIceGatheringDone();
        }
    }, role);
}

static int alpn_callback(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                  const unsigned char *in, unsigned int inlen, void *arg) {
    (void)ssl;
    (void)arg;
    if (SSL_select_next_proto((unsigned char **)out, outlen, alpn, sizeof(alpn),
                              in, inlen) != OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_ALERT_FATAL;

    return SSL_TLSEXT_ERR_OK;
}


static void onIceReceive(NiceAgent *agent, guint _stream_id, guint component_id, guint len, gchar *buf, gpointer data) {
    log(LOG_ICE, "cb_nice_recv: {}\n", len);
    BIO_write(quic_dgram_bio, buf, len);

    if (std::holds_alternative<RoleInitiator>(role)) {
        if (!quic_poll) {
            log(LOG_QUIC, "Initing listener\n");
            SSL_CTX_set_alpn_select_cb(quic_ssl_ctx, alpn_callback, NULL);

            quic_poll = SSL_new_listener(quic_ssl_ctx, 0);
            if (!quic_poll) {
                fatal_ossl("SSL_new_listener failed:\n");
            }
            SSL_set_blocking_mode(quic_poll, 0);


            BIO *dgram_for_ossl = nullptr;
            if (!BIO_new_bio_dgram_pair(&quic_dgram_bio, 1024 * 1024, &dgram_for_ossl, 1024 * 1024)) {
                fatal_ossl("BIO_new_bio_dgram_pair failed:\n");
            }

            // TODO possibly add capabilities?

            SSL_set_bio(quic_poll, dgram_for_ossl, dgram_for_ossl);
        }

        if (!quic_connection) {
            log(LOG_QUIC, "trying to accept connection\n");
            quic_connection = SSL_accept_connection(quic_poll, 0);
            if (quic_connection) {
                log(LOG_QUIC, "got connection\n");
            }
        }

        if (quic_connection && !quicConnectionUp) {
            if (SSL_is_init_finished(quic_connection)) {
                log(LOG_QUIC, "connection handshaked\n");
                SSL_set_default_stream_mode(quic_connection, SSL_DEFAULT_STREAM_MODE_NONE);
                quicConnectionUp = true;

                constexpr int exportLen = 32;
                guchar buf[exportLen];
                const char *label = "exporter auth peersock";
                int ret = SSL_export_keying_material(quic_connection, buf, exportLen, label, strlen(label), NULL, 0, 0);
                if (ret != 1) {
                    fatal_ossl("SSL_export_keying_material failed:\n");
                }
                log(LOG_AUTH, "Secret: {}\n", g_base64_encode(buf, exportLen));
                std::visit([&] (auto &role) {
                    if constexpr (std::is_same_v<typeof(role), std::monostate>) {
                        fatal("Bad role\n");
                    } else {
                        role.handleQuicConnected(std::string_view{(const char*)buf, exportLen});
                    }
                }, role);
            } else {
                log(LOG_QUIC, "connection handshake running\n");
            }
        }
    }
    iceStreamId = _stream_id;
    quicPoll();
}

static void quicPoll() {
    if (in_shutdown == ShutdownState::shutdownDone) {
        writeUserMessage({
                             {"event", "quit"},
                         },
                         "Quitting\n");
        exit(0);
        return;
    }

    if (quic_client) {
        // TODO(openssl-branch) crashes or errors out if quic_poll is listener
        int ret0 = SSL_handle_events(quic_poll);
        if (!ret0) {
            ERR_print_errors_fp(stderr);
        }
    } else if (quic_connection) {
        int ret0 = SSL_handle_events(quic_connection);
        if (!ret0) {
            ERR_print_errors_fp(stderr);
        }
    }

    int shutdown = SSL_get_shutdown(quic_client ? quic_client : quic_connection);
    if (shutdown) {
        log(LOG_QUIC, "Shutdown state: {}\n", shutdown);
    }

    if (in_shutdown == ShutdownState::shutdownPending) {
        int ret = SSL_shutdown(quic_client ? quic_client : quic_connection);
        if (ret < 0) {
            fatal_ossl("SSL_shutdown failed:\n");
        }
        in_shutdown = ret ? in_shutdown = ShutdownState::shutdownDone : ShutdownState::shutdownPending;

        if (in_shutdown == ShutdownState::shutdownDone) {
            writeUserMessage({
                                 {"event", "quit"},
                             },
                             "Quitting\n");
            exit(0);
            return;
        }
    } else if ((shutdown & (SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN)) == (SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN)) {
        // when shutdown from remote we need to poll for completed connection close
        int ret = SSL_shutdown(quic_client ? quic_client : quic_connection);
        if (ret < 0) {
            fatal_ossl("SSL_shutdown failed:\n");
        }
        if (ret) {
            writeUserMessage({
                                 {"event", "quit"},
                             },
                             "Quitting\n");
            exit(0);
            return;
        }
    } else if (shutdown == 0) {
        if (quic_client) {
            if (!quicConnectionUp) {
                int ret = SSL_connect(quic_client);
                if (ret == 0) {
                    fatal_ossl("SSL_connect implausible return: {}\n", ret);
                }
                if (ret == 1) {
                    log(LOG_QUIC, "Got connection\n");

                    if (SSL_is_init_finished(quic_client)) {
                        log(LOG_QUIC, "connection handshaked\n");
                    } else {
                        fatal("unexpected unfinished handshare after SSL_connect\n");
                    }
                    SSL_set_default_stream_mode(quic_client, SSL_DEFAULT_STREAM_MODE_NONE);

                    quicConnectionUp = true;

                    constexpr int exportLen = 32;
                    guchar buf[exportLen];
                    const char *label = "exporter auth peersock";
                    ret = SSL_export_keying_material(quic_client, buf, exportLen, label, strlen(label), NULL, 0, 0);
                    if (ret != 1) {
                        fatal_ossl("SSL_export_keying_material failed:\n");
                    }
                    log(LOG_AUTH, "Secret: {}/{}\n", ret, g_base64_encode(buf, exportLen));
                    std::visit([&] (auto &role) {
                        if constexpr (std::is_same_v<typeof(role), std::monostate>) {
                            fatal("Bad role\n");
                        } else {
                            role.handleQuicConnected(std::string_view{(const char*)buf, exportLen});
                        }
                    }, role);

                } else {
                    int ssl_error = SSL_get_error(quic_client, ret);
                    if (ssl_error != SSL_ERROR_WANT_READ && ssl_error != SSL_ERROR_WANT_WRITE) {
                        fatal_ossl("SSL_connect failed\n");
                    }
                }

            } else {
                SSL *new_stream = SSL_accept_stream(quic_client, 0);
                if (new_stream) {
                    log(LOG_QUIC, "quic on_stream_open: {}\n", SSL_get_stream_id(new_stream));
                    std::visit([&] (auto &role) {
                        if constexpr (std::is_same_v<typeof(role), std::monostate>) {
                            fatal("Bad role\n");
                        } else {
                            role.handleQuicStreamOpened(new_stream);
                        }
                    }, role);
                }
            }
        }

        if (quic_connection && quicConnectionUp) {
            SSL *new_stream = SSL_accept_stream(quic_connection, 0);
            if (new_stream) {
                log(LOG_QUIC, "quic on_stream_open: {}\n", SSL_get_stream_id(new_stream));
                std::visit([&] (auto &role) {
                    if constexpr (std::is_same_v<typeof(role), std::monostate>) {
                        fatal("Bad role\n");
                    } else {
                        role.handleQuicStreamOpened(new_stream);
                    }
                }, role);
            }
        }

        std::visit([&] (auto &role) {
            if constexpr (std::is_same_v<typeof(role), std::monostate>) {
                fatal("Bad role\n");
            } else {
                role.quicPoll();
            }
        }, role);
    }

    constexpr int buf_size = 1024*64;
    char buf[buf_size] = {0};

    int res = 0;
    do {
        res = BIO_read(quic_dgram_bio, buf, buf_size);
        if (res > 0) {
            log(LOG_QUIC, "sending datagrams with len {}\n", res);
            NiceOutputMessage msg;
            GOutputVector vec;
            msg.n_buffers = 1;
            msg.buffers = &vec;
            vec.size = res;
            vec.buffer = buf;
            //nice_agent_send_messages_nonblocking(iceAgent, iceStreamId, 1, &msg, 1, nullptr, nullptr);
            int ret = nice_agent_send(iceAgent, iceStreamId, 1, res, buf);
            if (ret <= 0) {
                log(LOG_ICE, "failed to send dgram {:x}\n", ret);
            }
        }

    } while (res > 0);

    struct timeval tv;
    int is_infinite;

    if (SSL_get_event_timeout(quic_connection ? quic_connection : quic_poll, &tv, &is_infinite)) {
        if (tv.tv_sec == 0 && tv.tv_usec == 0) {
            // immediate processing needed
        } else if (!is_infinite) {
            int milli_seconds = tv.tv_sec * 1000 + tv.tv_usec / 1000;
            log(LOG_QUIC, "quicPoll rescheduled in {}ms\n", milli_seconds);
            ++timer_generation;
            // TODO: Remove older timeout sources by id? see g_source_remove()
            g_timeout_add(milli_seconds, &onQuicPollTimeout, (void*)(intptr_t)timer_generation);
        }
    }
}


static void initQuic(bool server) {
    // dummy cert, this not actually used for security
    const char *dummyCertPem = R"(-----BEGIN CERTIFICATE-----
MIIDAzCCAeugAwIBAgIUfZdoAJDHP14C9nLnGdyaIueYrrowDQYJKoZIhvcNAQEL
BQAwEDEOMAwGA1UEAwwFZHVtbXkwIBcNMjExMDIyMTkxMTIyWhgPMjEyMTA5Mjgx
OTExMjJaMBAxDjAMBgNVBAMMBWR1bW15MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAy85gKxNXv0M3VHFm23YOhnE4FsFyNnDfqvfdEzg2kFxNAmOjDmvK
ZL7FoYnHeT+6Svxekrt/Gx+DCXg5hTT3Zwo7nSYiXN2v7PMMCEJt/vmuqvLnrRhd
2J/DIazI+CBNHQvtOHKwiuysuTEeI37FHW68HHCYLhR75ZLKhPB7lRra+TdVDwJN
hR9QGk1vxvbOcsweJ9ymuLrmS7Z78GQX3CSHN1Q+vx10uB+InM6gfwl/BHWRHE2q
gjmjQXp1sYeWu3cXXSMEwdZXDYd+/h1vPRQbfA2MGfcWX93Jf/FjMrpTZu3VCxXr
/1m4+21HgIHiQWfHics1c9b1MHw20dTtpwIDAQABo1MwUTAdBgNVHQ4EFgQUYLoq
MA/D0iIkF9jxKFH0v9Kk1uwwHwYDVR0jBBgwFoAUYLoqMA/D0iIkF9jxKFH0v9Kk
1uwwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAasuWcJlIgqkg
IBb/1hUMAEiJ8ml7c4dY2TzlbfRVgAg1M0Scyo/GAwEmA2BLZrXVviUIloGlzDsM
r5gQR86jPUtm02/OwHbrxo1bS+DU44O6vCNafZvMcUwXsO2ja9PVXUUg3ZL9sX3F
5M5/MM5rHc1AO3pHAOq7EUMs1qT98uYModDzGchv46Jc0ZqOp/gX2nRJnNVRUB6V
Nfm/YN6A9tpmfhFsdzLsxE1/u8MyghK10XZ7Q0OLkBXte74nKUbtWXT6GzgewImq
WuTawHzzrgeOCKZR5kAef3fvDGu9Vf3ysLCp4W8jpxWIUMpe/LtckdII3EQHJxch
JIEN9D5WRg==
-----END CERTIFICATE-----)";
    static std::vector<uint8_t> dummyCert = {
        0x30, 0x82, 0x03, 0x03, 0x30, 0x82, 0x01, 0xeb, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x7d, 0x97, 0x68, 0x00, 0x90, 0xc7, 0x3f, 0x5e, 0x02,
        0xf6, 0x72, 0xe7, 0x19, 0xdc, 0x9a, 0x22, 0xe7, 0x98, 0xae, 0xba, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
        0x05, 0x00, 0x30, 0x10, 0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x05, 0x64, 0x75, 0x6d, 0x6d, 0x79, 0x30, 0x20, 0x17, 0x0d,
        0x32, 0x31, 0x31, 0x30, 0x32, 0x32, 0x31, 0x39, 0x31, 0x31, 0x32, 0x32, 0x5a, 0x18, 0x0f, 0x32, 0x31, 0x32, 0x31, 0x30, 0x39, 0x32, 0x38, 0x31,
        0x39, 0x31, 0x31, 0x32, 0x32, 0x5a, 0x30, 0x10, 0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x05, 0x64, 0x75, 0x6d, 0x6d, 0x79,
        0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00,
        0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xcb, 0xce, 0x60, 0x2b, 0x13, 0x57, 0xbf, 0x43, 0x37, 0x54, 0x71, 0x66, 0xdb, 0x76, 0x0e,
        0x86, 0x71, 0x38, 0x16, 0xc1, 0x72, 0x36, 0x70, 0xdf, 0xaa, 0xf7, 0xdd, 0x13, 0x38, 0x36, 0x90, 0x5c, 0x4d, 0x02, 0x63, 0xa3, 0x0e, 0x6b, 0xca,
        0x64, 0xbe, 0xc5, 0xa1, 0x89, 0xc7, 0x79, 0x3f, 0xba, 0x4a, 0xfc, 0x5e, 0x92, 0xbb, 0x7f, 0x1b, 0x1f, 0x83, 0x09, 0x78, 0x39, 0x85, 0x34, 0xf7,
        0x67, 0x0a, 0x3b, 0x9d, 0x26, 0x22, 0x5c, 0xdd, 0xaf, 0xec, 0xf3, 0x0c, 0x08, 0x42, 0x6d, 0xfe, 0xf9, 0xae, 0xaa, 0xf2, 0xe7, 0xad, 0x18, 0x5d,
        0xd8, 0x9f, 0xc3, 0x21, 0xac, 0xc8, 0xf8, 0x20, 0x4d, 0x1d, 0x0b, 0xed, 0x38, 0x72, 0xb0, 0x8a, 0xec, 0xac, 0xb9, 0x31, 0x1e, 0x23, 0x7e, 0xc5,
        0x1d, 0x6e, 0xbc, 0x1c, 0x70, 0x98, 0x2e, 0x14, 0x7b, 0xe5, 0x92, 0xca, 0x84, 0xf0, 0x7b, 0x95, 0x1a, 0xda, 0xf9, 0x37, 0x55, 0x0f, 0x02, 0x4d,
        0x85, 0x1f, 0x50, 0x1a, 0x4d, 0x6f, 0xc6, 0xf6, 0xce, 0x72, 0xcc, 0x1e, 0x27, 0xdc, 0xa6, 0xb8, 0xba, 0xe6, 0x4b, 0xb6, 0x7b, 0xf0, 0x64, 0x17,
        0xdc, 0x24, 0x87, 0x37, 0x54, 0x3e, 0xbf, 0x1d, 0x74, 0xb8, 0x1f, 0x88, 0x9c, 0xce, 0xa0, 0x7f, 0x09, 0x7f, 0x04, 0x75, 0x91, 0x1c, 0x4d, 0xaa,
        0x82, 0x39, 0xa3, 0x41, 0x7a, 0x75, 0xb1, 0x87, 0x96, 0xbb, 0x77, 0x17, 0x5d, 0x23, 0x04, 0xc1, 0xd6, 0x57, 0x0d, 0x87, 0x7e, 0xfe, 0x1d, 0x6f,
        0x3d, 0x14, 0x1b, 0x7c, 0x0d, 0x8c, 0x19, 0xf7, 0x16, 0x5f, 0xdd, 0xc9, 0x7f, 0xf1, 0x63, 0x32, 0xba, 0x53, 0x66, 0xed, 0xd5, 0x0b, 0x15, 0xeb,
        0xff, 0x59, 0xb8, 0xfb, 0x6d, 0x47, 0x80, 0x81, 0xe2, 0x41, 0x67, 0xc7, 0x89, 0xcb, 0x35, 0x73, 0xd6, 0xf5, 0x30, 0x7c, 0x36, 0xd1, 0xd4, 0xed,
        0xa7, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x53, 0x30, 0x51, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x60, 0xba, 0x2a,
        0x30, 0x0f, 0xc3, 0xd2, 0x22, 0x24, 0x17, 0xd8, 0xf1, 0x28, 0x51, 0xf4, 0xbf, 0xd2, 0xa4, 0xd6, 0xec, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23,
        0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x60, 0xba, 0x2a, 0x30, 0x0f, 0xc3, 0xd2, 0x22, 0x24, 0x17, 0xd8, 0xf1, 0x28, 0x51, 0xf4, 0xbf, 0xd2, 0xa4,
        0xd6, 0xec, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0d, 0x06, 0x09, 0x2a,
        0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x6a, 0xcb, 0x96, 0x70, 0x99, 0x48, 0x82, 0xa9, 0x20,
        0x20, 0x16, 0xff, 0xd6, 0x15, 0x0c, 0x00, 0x48, 0x89, 0xf2, 0x69, 0x7b, 0x73, 0x87, 0x58, 0xd9, 0x3c, 0xe5, 0x6d, 0xf4, 0x55, 0x80, 0x08, 0x35,
        0x33, 0x44, 0x9c, 0xca, 0x8f, 0xc6, 0x03, 0x01, 0x26, 0x03, 0x60, 0x4b, 0x66, 0xb5, 0xd5, 0xbe, 0x25, 0x08, 0x96, 0x81, 0xa5, 0xcc, 0x3b, 0x0c,
        0xaf, 0x98, 0x10, 0x47, 0xce, 0xa3, 0x3d, 0x4b, 0x66, 0xd3, 0x6f, 0xce, 0xc0, 0x76, 0xeb, 0xc6, 0x8d, 0x5b, 0x4b, 0xe0, 0xd4, 0xe3, 0x83, 0xba,
        0xbc, 0x23, 0x5a, 0x7d, 0x9b, 0xcc, 0x71, 0x4c, 0x17, 0xb0, 0xed, 0xa3, 0x6b, 0xd3, 0xd5, 0x5d, 0x45, 0x20, 0xdd, 0x92, 0xfd, 0xb1, 0x7d, 0xc5,
        0xe4, 0xce, 0x7f, 0x30, 0xce, 0x6b, 0x1d, 0xcd, 0x40, 0x3b, 0x7a, 0x47, 0x00, 0xea, 0xbb, 0x11, 0x43, 0x2c, 0xd6, 0xa4, 0xfd, 0xf2, 0xe6, 0x0c,
        0xa1, 0xd0, 0xf3, 0x19, 0xc8, 0x6f, 0xe3, 0xa2, 0x5c, 0xd1, 0x9a, 0x8e, 0xa7, 0xf8, 0x17, 0xda, 0x74, 0x49, 0x9c, 0xd5, 0x51, 0x50, 0x1e, 0x95,
        0x35, 0xf9, 0xbf, 0x60, 0xde, 0x80, 0xf6, 0xda, 0x66, 0x7e, 0x11, 0x6c, 0x77, 0x32, 0xec, 0xc4, 0x4d, 0x7f, 0xbb, 0xc3, 0x32, 0x82, 0x12, 0xb5,
        0xd1, 0x76, 0x7b, 0x43, 0x43, 0x8b, 0x90, 0x15, 0xed, 0x7b, 0xbe, 0x27, 0x29, 0x46, 0xed, 0x59, 0x74, 0xfa, 0x1b, 0x38, 0x1e, 0xc0, 0x89, 0xaa,
        0x5a, 0xe4, 0xda, 0xc0, 0x7c, 0xf3, 0xae, 0x07, 0x8e, 0x08, 0xa6, 0x51, 0xe6, 0x40, 0x1e, 0x7f, 0x77, 0xef, 0x0c, 0x6b, 0xbd, 0x55, 0xfd, 0xf2,
        0xb0, 0xb0, 0xa9, 0xe1, 0x6f, 0x23, 0xa7, 0x15, 0x88, 0x50, 0xca, 0x5e, 0xfc, 0xbb, 0x5c, 0x91, 0xd2, 0x08, 0xdc, 0x44, 0x07, 0x27, 0x17, 0x21,
        0x24, 0x81, 0x0d, 0xf4, 0x3e, 0x56, 0x46
    };

    const char *dummyKey = R"(-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDLzmArE1e/QzdU
cWbbdg6GcTgWwXI2cN+q990TODaQXE0CY6MOa8pkvsWhicd5P7pK/F6Su38bH4MJ
eDmFNPdnCjudJiJc3a/s8wwIQm3++a6q8uetGF3Yn8MhrMj4IE0dC+04crCK7Ky5
MR4jfsUdbrwccJguFHvlksqE8HuVGtr5N1UPAk2FH1AaTW/G9s5yzB4n3Ka4uuZL
tnvwZBfcJIc3VD6/HXS4H4iczqB/CX8EdZEcTaqCOaNBenWxh5a7dxddIwTB1lcN
h37+HW89FBt8DYwZ9xZf3cl/8WMyulNm7dULFev/Wbj7bUeAgeJBZ8eJyzVz1vUw
fDbR1O2nAgMBAAECggEAMDOjMwzkF+xBzcr0VLtbPBjS9y7RYGbZv4nX04/b99Cc
tg/ypJqBx8oG2+nGL7sOyGVfyLxnl3age0Df+c1JJimZZ9V5ExWrYhMpqVpswX0z
/mJswNeeenluoSxIa8bX9iK3/D3D21eWkkY3ppV48TkbbG6Ez4EwvF83XrGxyNWg
vBhH6Ca5twBEj94zw9G/unBwRn73xw8N32SCQg83BdAXfDUu2VCZQYKEvrT39Dog
UTownYp5+3K7utnDrtor2TTQwB+DX7V21Y34KxHUu4N3MndoTrtkG7daDdtunPVr
kmqR5DHpckAqlGYfvwtrBs8H7Oj5vqRyo5dkGw7+YQKBgQD4vfVMRplZ5TwjrByd
ooC0O+qaOuXxc1QsSaAIeVvwjVFFkEEngxuT2bqPLJzVcyl9AbaW4InCrsjTGu2I
elTRQl6er1yCR92sWrXR6uA90MCpiXJg9ajFlOLoNJK/XhuoqDW/kVuLxC/wEGix
tAJLCWIeAyDVWSdjCc7qK2AeNQKBgQDRwMHvaC0y0d2QttDmuJ55rKvTfCNUhOiY
E58ce009OW9YcKBaLrzMa4MQAxf76hTqonLXOUURz6nGNvnTPfjrmj+/WjMP3guV
1pzcsMUXTjKADbczO3/iFWCn/xtP/PwSzJ+RoZF0cbS0bb96sWz+C2UDo5Y/eYSs
gprwQGbH6wKBgQDs9vqS+cbp7wqF6VcxjTgTe+kZmPaqOPZ9Yn6E1CiUV+yO2shX
Pf2tsoSaFSQr7JQftNwfjDVxNFW5VzPnCrN2z0WY4vK8Yn55zcjc/Gc4PIDugjRm
zmFEKXypPjx29s5etDDQGUgfNH1+tAMpF5X/qibA9LX4ygBNx3BJgZ0F6QKBgQCk
WAhb4V8Qo3ibi3IQZHTe1tjmYix4a46moTEYqs9w+hBw1gX9wwLwlAhjwljHa7gp
w1CBq4CfnPrjsG18AuGHEBuEfVLmys5+/2F2VRaH1SAiTxzMioD/jkpmNq6atJh4
zlT0UQhbmT/B4v+VTXEdd6YU/NabM0YtuENXnM4rMwKBgGjsuqMyLrPC496WsQ7b
uSRn2+Rh1dgOcPr+UHsxLgrfqNhKmpHo8HxrxPfGWjSDS3x5uvrt3PbgITEaDH/P
asGx89bMGyzB5fXH9FInTHB2Q5ToGJU/xU0ycmNIcVNVx5zL1RmC7bF6VeJdoMzv
Ckoxer9nbxHB68Fok8EBk0nA
-----END PRIVATE KEY-----)";

    BIO *bio = BIO_new_mem_buf(dummyKey, -1);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!pkey) {
        fatal_ossl("PEM_read_bio_PrivateKey failed:\n");
    }
    BIO_free(bio);

    if (server) {
        quic_ssl_ctx = SSL_CTX_new(OSSL_QUIC_server_method());
    } else {
        quic_ssl_ctx = SSL_CTX_new(OSSL_QUIC_client_method());
    }
    SSL_CTX_use_PrivateKey(quic_ssl_ctx, pkey);
    EVP_PKEY_free(pkey);
    SSL_CTX_use_certificate_ASN1(quic_ssl_ctx, dummyCert.size(), dummyCert.data());

    /*
    TODO set transport_params max_idle_timeout
    */

    X509_STORE *store = X509_STORE_new();
    auto *dummyCertPemBio = BIO_new(BIO_s_mem());
    BIO_puts(dummyCertPemBio, dummyCertPem);
    auto *dummyCertObj = PEM_read_bio_X509(dummyCertPemBio, NULL, 0, NULL);
    BIO_free(dummyCertPemBio);
    X509_STORE_add_cert(store, dummyCertObj);
    SSL_CTX_set_cert_store(quic_ssl_ctx, store);
}


static void init() {
    otrl_sm_init();
    otrl_sm_state_new(&authState);

    soupSession = soup_session_new();

    SoupMessage *msg = soup_message_new(SOUP_METHOD_GET, mailboxServer.data());

    initQuic(std::holds_alternative<RoleInitiator>(role));

    soup_session_websocket_connect_async(soupSession, msg, NULL, NULL, NULL, (GAsyncReadyCallback)OnRendConnection, NULL);
}


void applyConfigDefaults(PeersockConfig &config) {
    if (config.stunServer.empty()) {
        config.stunServer = "freestun.net";
    }

    if (!config.stunPort) {
        config.stunPort = 3479;
    }
}

void startFromCode(const std::string &code, std::unique_ptr<ModeBase> &&mode_, PeersockConfig config) {
    init();
    applyConfigDefaults(config);
    mode = std::move(mode_);
    role = RoleFromCode{code, config};
}

void startGeneratingCode(std::function<void(std::string)> codeCallback_, std::unique_ptr<ModeBase> &&mode_, PeersockConfig config) {
    init();
    applyConfigDefaults(config);
    mode = std::move(mode_);
    codeCallback = codeCallback_;
    role = RoleInitiator(config);
}

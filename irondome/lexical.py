"""Lexical features of DNS query names (PS threat class c).

The DGA detector scores the *second-level label* of each queried domain
(e.g. "xkqzjwpt" in "xkqzjwpt.info") with character statistics, a character bigram
language model, dictionary coverage and how common the domain's suffix is.

The bigram model, vocabulary and suffix frequencies come from lexical_model.json,
which model_training_pipeline.py builds from the *training* partition of a real
top-sites list (Tranco). Without that file the embedded word list is used. Nothing
is downloaded at run time.
"""

from __future__ import annotations

import json
import math
from pathlib import Path

from .netutil import split_domain, str_entropy

# fmt: off
WORDS = """
able about above access account acid act action active actor adapt add admin adult advance advice affair
after again age agency agent agree air airline alarm album alert alien align alive alpha amazing amber
anchor angel angle animal answer apple apply april arch area arena argue army around arrow art article
artist asset atlas atom audio august author auto avenue award away baby back bad badge bag bake balance
ball band bank bar base basic basket battle bay beach beam bean bear beat beauty become bed bee begin
bell belt bench best better beyond bike bill bird birth bit black blade blank blast blend bless block
blog blood bloom blue board boat body bold bond bone bonus book boost boot border boss bottle bottom
bounce bowl box brain branch brand brave bread break brick bridge brief bright bring broad brother
brown brush buddy budget build bulk bull bunch burn bus bush business busy butter button buy buzz
cabin cable cafe cake call calm camera camp can canal candy canvas cap capital captain car carbon card
care career cargo carry cart case cash cast castle cat catch cause cave cell center central chain chair
chalk champion chance change channel chapter charge chart chase chat cheap check cheese chef chess chief
child chip choice circle city civic claim class clean clear clever click client cliff climb clinic clock
close cloud club coach coast code coffee coin cold collect college color column combo come comfort
comic common company compare complete computer concept connect contact content control cook cool copper
copy coral core corner cost cotton count country couple courage course court cover craft crane crash
crazy cream create credit crew cricket crisp cross crowd crown cruise crystal cube culture cup cure
curve custom cyber cycle daily dairy dance danger dark data date dawn day deal dear debate decade decide
deep deer defend delta demand dental depot design desk detail develop device dial diamond diary diet
digital dinner direct discover dish disk distance divide doctor dollar domain door double dove down
dragon drama draw dream dress drift drink drive drop drum duck dust duty eagle early earn earth east
easy echo eco edge edit educate effect eight elder electric element elite email ember empire employ
empty end energy engine enjoy enter entry equal era error escape essay estate event ever every exact
exam example exchange exit expert explore express extra eye fabric face fact factor factory faith fall
fame family fan fancy farm fashion fast father feast feather feature federal fee feed feel fellow fence
festival fever field fifth fight figure file film filter final finance find fine finger finish fire
firm first fish fit five fix flag flame flash fleet flight flip float flood floor flower fluid fly
focus fold folk follow food foot force forest forge form fort fortune forum forward found fox frame
free fresh friend frog front frost fruit fuel fun fund future galaxy game garden gas gate gather gear
gem general genius gentle giant gift ginger girl give glad glass global glory glove glow goal goat gold
golden golf good grace grade grain grand grant graph grass gravity great green grid grill ground group
grow guard guest guide guitar gulf hair half hall hammer hand happy harbor hard harmony harvest hat
hawk head health heart heat heaven heavy help herb hero hidden high hill hint history hobby hold holiday
home honey honor hope horizon horse host hot hotel hour house human humble hunt ice icon idea image
impact income index india indigo industry info inner input insight inspire insure intel invest iron
island item ivory jacket jade jazz jet jewel job join journal journey joy judge juice jump jungle
junior just keen keep kernel key kid kind king kit kitchen kite knight know lab label lake lamp land
lane language laptop large laser last late launch law layer lead leaf learn legal legend lemon level
liberty library life light lime limit line link lion list little live loan local lock logic long loop
lord lotus love lucky lunar lunch machine magic magnet mail main major maker mall manage mango manual
map maple marble march marine mark market mars mask master match matrix max media medical meet melody
member memory mental menu merchant merit metal meter method metro micro middle mild mile milk mill
mind mine mint minute mirror mission mix mobile model modern moment money monitor monkey month moon
more morning mother motion motor mountain mouse move movie much music nation native nature navy near
neat nest net network new news next nice night noble node north note novel now number nurse nut oak
ocean offer office oil old olive omega one online open opera option orange orbit order organic origin
outer output owl owner oxygen pace pack page paint pair palace palm panda panel paper parade park part
party pass past path patient pattern peace peak pearl pen people pepper perfect person pet phone photo
piano pick picture piece pilot pine pink pioneer pixel pizza place plain plan planet plant plate play
plaza plus pocket poem point polar police policy pool popular port portal post power press price pride
prime print prize pro produce profit program project promise proof proper pulse pure purple push
puzzle quality quantum quarter queen quest quick quiet quote race radar radio rain rainbow range rapid
rate raven ready real reason record red reform region relax remote rent repair report rescue resort
rest result retail review reward rhythm rice rich ride right ring rise river road robot rock rocket
role roof room root rose round route royal ruby rule run rural safe sage sail salad sale salt sample
sand satellite save scale scan scene school science score scout screen sea search season seat second
secret secure seed select sell send senior sense series serve service seven shadow shape share shark
sharp shell shield shift shine ship shop shore short show side sight sign signal silk silver simple
single sister site six size skill sky slate sleep slice slide smart smile smooth snow social soft solar
solid solution song sonic sound source south space spark speak special speed spice spirit split sport
spot spring square staff stage stand star start state station steel step stick stock stone store
storm story stream street strong student studio style sugar summer summit sun super supply support
surf swan sweet swift symbol system table tailor talent talk tank target task taste tea teach team tech
temple ten tennis term test text thank theory thing think third thread three thunder ticket tiger
time tiny title today token tool top topic torch total touch tour tower town toy track trade traffic
trail train travel treasure tree trend trial tribe trip truck true trust truth tune turbo turn twin
type ultra uncle union unique unit unity universe update urban user valley value vector velvet venture
verse video view village vintage violet virtual vision visit vista vital voice volt vote voyage wagon
walk wall wallet water wave way wealth weather web week well west whale wheel white wide wild wind
window wine wing winner winter wire wise wolf wonder wood word work world worth write yard year yellow
yoga young youth zebra zero zone
""".split()

# Common Indian name / business tokens so domains like shreeganeshtraders.in read as benign.
INDIAN_TOKENS = """
aadhaar agro ambika amrit anand apna ashok balaji bharat bhavan bhoomi bihar chandra chennai
delhi desh devi dhan disha durga gajanan ganesh ganga gokul gopal govind gujarat gyan hari
hind hindustan indra indus jai jaipur jan janata jeevan jyoti kalyan kamal karnataka kerala
kisan krishna kumar lakshmi laxmi madhav maha mahal mahindra mangal mata mitra mumbai nagar
narmada nav navin nidhi om padma parivar patel pragati prakash prem pune punjab raj rajesh
ram rama rashtra ravi sagar sahyog sai samachar sampark sanchar sangam sanskriti saraswati
sarkar seva shakti sharma shiv shree shri shubh siddhi singh sri sudha surya swadesh tata
telangana trimurti udyog uttam vadodara vani vardhan vasudha veda vidya vijay vikas vishwa
yatra yojana
""".split()

BENIGN_DOMAINS = """
google.com youtube.com facebook.com instagram.com whatsapp.com twitter.com x.com linkedin.com wikipedia.org
amazon.com amazon.in flipkart.com microsoft.com windows.com office.com live.com outlook.com bing.com msn.com
apple.com icloud.com netflix.com hotstar.com primevideo.com spotify.com zoom.us slack.com github.com
gitlab.com stackoverflow.com reddit.com quora.com medium.com wordpress.com blogger.com tumblr.com
yahoo.com duckduckgo.com mozilla.org firefox.com cloudflare.com akamai.com fastly.com cloudfront.net
amazonaws.com azure.com googleapis.com gstatic.com googleusercontent.com doubleclick.net
googlesyndication.com adobe.com dropbox.com box.com salesforce.com oracle.com ibm.com intel.com
nvidia.com samsung.com xiaomi.com oneplus.com dell.com hp.com lenovo.com asus.com cisco.com
paypal.com paytm.com phonepe.com razorpay.com sbi.co.in onlinesbi.sbi hdfcbank.com icicibank.com
axisbank.com kotak.com pnbindia.in bankofbaroda.in rbi.org.in npci.org.in irctc.co.in indianrail.gov.in
gov.in india.gov.in nic.in uidai.gov.in incometax.gov.in gst.gov.in digilocker.gov.in mygov.in
cowin.gov.in isro.gov.in drdo.gov.in ntro.gov.in cert-in.org.in meity.gov.in aicte-india.org ugc.ac.in
iitb.ac.in iitd.ac.in iitm.ac.in iisc.ac.in ahduni.edu.in nptel.ac.in swayam.gov.in
timesofindia.com hindustantimes.com ndtv.com thehindu.com indianexpress.com livemint.com
economictimes.com moneycontrol.com zeebiz.com news18.com indiatoday.in bbc.co.uk bbc.com cnn.com
nytimes.com theguardian.com reuters.com bloomberg.com forbes.com wsj.com
zomato.com swiggy.com makemytrip.com goibibo.com bookmyshow.com olacabs.com uber.com myntra.com
ajio.com nykaa.com meesho.com snapdeal.com bigbasket.com blinkit.com zeptonow.com jiomart.com
airtel.in jio.com vodafone.in bsnl.co.in tatasky.com tataplay.com reliance.com tata.com infosys.com
wipro.com tcs.com hcltech.com techmahindra.com zoho.com freshworks.com naukri.com shiksha.com
byjus.com unacademy.com vedantu.com coursera.org udemy.com edx.org khanacademy.org
openai.com anthropic.com chatgpt.com claude.ai huggingface.co kaggle.com
ubuntu.com debian.org archlinux.org python.org pypi.org npmjs.com nodejs.org docker.com
kubernetes.io apache.org nginx.org mongodb.com postgresql.org mysql.com redis.io
steamcommunity.com steampowered.com epicgames.com playstation.com xbox.com twitch.tv discord.com
telegram.org signal.org skype.com teams.microsoft.com webex.com
imdb.com yelp.com tripadvisor.com booking.com airbnb.com expedia.com
weather.com accuweather.com imd.gov.in maps.google.com openstreetmap.org
ntp.org pool.ntp.org time.windows.com time.apple.com
""".split()
# fmt: on

WORDS = WORDS + INDIAN_TOKENS
WORD_SET = frozenset(WORDS)

POPULAR_TLDS = frozenset(
    "com net org in edu gov io co uk us de fr jp au ca ai app dev me tv info biz".split()
)
ABUSED_TLDS = frozenset(
    "xyz top tk ml ga cf gq pw cc ws club online site space icu buzz su ru cn win bid loan work "
    "click link rest fun monster cyou sbs cfd lol".split()
)

_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789-"
_VOWELS = frozenset("aeiou")
_HEX = frozenset("0123456789abcdef")


def _train_bigrams() -> dict[str, float]:
    corpus = list(WORDS)
    for d in BENIGN_DOMAINS:
        _, sld, _ = split_domain(d)
        if sld:
            corpus.append(sld)
    return _bigram_table(corpus)


def _bigram_table(corpus) -> dict[str, float]:
    counts: dict[str, int] = {}
    firsts: dict[str, int] = {}
    symbols = "^" + _ALPHABET + "$"
    for w in corpus:
        s = "^" + w + "$"
        for a, b in zip(s, s[1:]):
            counts[a + b] = counts.get(a + b, 0) + 1
            firsts[a] = firsts.get(a, 0) + 1
    v = len(symbols)
    table = {}
    for a in symbols:
        denom = firsts.get(a, 0) + v
        for b in symbols:
            table[a + b] = math.log10((counts.get(a + b, 0) + 1) / denom)
    return table


BIGRAM_LOGP = _train_bigrams()
_BIGRAM_FLOOR = min(BIGRAM_LOGP.values())

# ---------------------------------------------------------------------------
# Lexical model learned from a real benign corpus (optional, see module doc)
# ---------------------------------------------------------------------------
LEXICAL_MODEL_PATH = Path(__file__).with_name("lexical_model.json")
TLD_RARITY: dict[str, float] = {}   # suffix -> -log10(share of benign domains using it)
_TLD_UNSEEN = 5.0
# suffixes of the deployment's own country are ordinary there even if rare globally
HOME_SUFFIXES = frozenset("in co.in gov.in ac.in org.in net.in nic.in edu.in res.in firm.in gen.in ind.in".split())


def build_lexical_model(domains, source: str = "") -> dict:
    """Bigram table, vocabulary and suffix rarity from a list of benign registered domains."""
    slds, suffix_counts, token_counts = [], {}, {}
    for d in domains:
        _, sld, suffix = split_domain(d)
        if not sld:
            continue
        slds.append(sld)
        suffix_counts[suffix] = suffix_counts.get(suffix, 0) + 1
        for tok in sld.split("-"):
            if tok.isalpha() and 3 <= len(tok) <= 12:
                token_counts[tok] = token_counts.get(tok, 0) + 1
    vocab = ({t for t, c in token_counts.items() if c >= 2}
             | {x for x in slds[:5000] if x.isalpha() and 4 <= len(x) <= 12})
    total, v = sum(suffix_counts.values()), len(suffix_counts) + 1
    rarity = {sfx: min(5.0, -math.log10((c + 1) / (total + v))) for sfx, c in suffix_counts.items()}
    for sfx in HOME_SUFFIXES:
        rarity[sfx] = min(rarity.get(sfx, 5.0), 1.0)
    return {
        "version": 1,
        "source": source,
        "corpus_domains": len(slds),
        "bigram_logp": {k: round(val, 5) for k, val in _bigram_table(list(WORDS) + slds).items()},
        "vocabulary": sorted(vocab),
        "tld_rarity": {k: round(val, 4) for k, val in sorted(rarity.items())},
        "tld_unseen": round(min(5.0, -math.log10(1 / (total + v))), 4),
    }


def _load_lexical_model():
    global BIGRAM_LOGP, _BIGRAM_FLOOR, WORD_SET, _TLD_UNSEEN
    if not LEXICAL_MODEL_PATH.exists():
        return None
    doc = json.loads(LEXICAL_MODEL_PATH.read_text(encoding="utf-8"))
    BIGRAM_LOGP = doc["bigram_logp"]
    _BIGRAM_FLOOR = min(BIGRAM_LOGP.values())
    WORD_SET = frozenset(WORDS) | frozenset(doc["vocabulary"])
    TLD_RARITY.update(doc["tld_rarity"])
    _TLD_UNSEEN = doc["tld_unseen"]
    return {k: doc[k] for k in ("version", "source", "corpus_domains")}


LEXICAL_MODEL = _load_lexical_model()


def bigram_score(label: str) -> float:
    """Mean log10 probability of the label's character bigrams (higher = more English-like)."""
    s = "^" + label + "$"
    pairs = list(zip(s, s[1:]))
    if not pairs:
        return _BIGRAM_FLOOR
    return sum(BIGRAM_LOGP.get(a + b, _BIGRAM_FLOOR) for a, b in pairs) / len(pairs)


def dict_coverage(label: str) -> float:
    """Fraction of characters covered by dictionary words (greedy longest match, words >= 3 chars)."""
    n = len(label)
    if n == 0:
        return 0.0
    i = covered = 0
    while i < n:
        for L in range(min(12, n - i), 2, -1):
            if label[i : i + L] in WORD_SET:
                covered += L
                i += L
                break
        else:
            i += 1
    return covered / n


def _max_run(label: str, predicate) -> int:
    best = cur = 0
    for ch in label:
        if predicate(ch):
            cur += 1
            best = max(best, cur)
        else:
            cur = 0
    return best


def tld_rarity(suffix: str) -> float:
    """How unusual the domain's public suffix is among benign domains (0 = very common).
    Learned from the real corpus when lexical_model.json exists, else a coarse 0/1/2 scale."""
    if TLD_RARITY:
        return TLD_RARITY.get(suffix, TLD_RARITY.get(suffix.rsplit(".", 1)[-1], _TLD_UNSEEN))
    tld = suffix.rsplit(".", 1)[-1] if suffix else ""
    if tld in POPULAR_TLDS:
        return 0
    if tld in ABUSED_TLDS:
        return 2
    return 1


DOMAIN_FEATURES = [
    "length", "entropy", "digit_ratio", "vowel_ratio", "consonant_max_run", "digit_max_run",
    "unique_char_ratio", "hex_ratio", "bigram_score", "dict_coverage", "hyphen_count",
    "tld_rarity",
]


def domain_features(qname: str) -> dict[str, float]:
    """Lexical feature vector for a query name, computed on its second-level label."""
    sub, sld, suffix = split_domain(qname)
    label = sld or qname
    n = max(1, len(label))
    letters = [c for c in label if c.isalpha()]
    return {
        "length": float(len(label)),
        "entropy": str_entropy(label),
        "digit_ratio": sum(c.isdigit() for c in label) / n,
        "vowel_ratio": (sum(c in _VOWELS for c in letters) / len(letters)) if letters else 0.0,
        "consonant_max_run": float(_max_run(label, lambda c: c.isalpha() and c not in _VOWELS)),
        "digit_max_run": float(_max_run(label, str.isdigit)),
        "unique_char_ratio": len(set(label)) / n,
        "hex_ratio": sum(c in _HEX for c in label) / n,
        "bigram_score": bigram_score(label),
        "dict_coverage": dict_coverage(label),
        "hyphen_count": float(label.count("-")),
        "tld_rarity": float(tld_rarity(suffix)),
        "n_labels": float(qname.count(".") + 1),
        "sub_length": float(len(sub)),
    }

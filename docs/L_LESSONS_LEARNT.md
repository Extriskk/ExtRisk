# L blog — extension analysis lessons learnt

Populated by `scripts/l_crawler.py`. Used by Bablu and the detection library.

Run from repo root:

```bash
python scripts/l_crawler.py --max-posts 30 --write-lessons
```

Output: `data/l/l_posts.json`, `data/l/l_consolidated.json`, and this file (consolidated IOCs + detection hints).

## Detection rules added from security research

The following were added to the static analyzer based on security research blog analyses (ChatGPT account theft, Sleeper Sound, 40+ extensions, etc.):

| Rule | Location | Source |
|------|----------|--------|
| **Fetch API hook / override** | `static_analyzer.py` malicious_patterns | Session token interception via `window.fetch` override |
| **Authorization header extraction** | `static_analyzer.py` malicious_patterns | Reading `headers.get("authorization")` from hooked fetch |
| **Content script in MAIN world** | `static_analyzer.py` (manifest check) | MAIN world enables access to in-memory tokens and page `window.fetch` |

## Bablu / detection library mapping

- **Session token interception**: Research reports `window.fetch` hooking + MAIN world content script to read Authorization headers. Our scanner: check for `fetch` override/hook and `world: "MAIN"` in manifest content_scripts.
- **Extension IDs below**: Add to IOC database or blocklist for correlation.
- **Domains below**: Add to domain intelligence / blocklist for network and publisher checks.

# L blog — extension analysis lessons learnt

Populated by `scripts/l_crawler.py`. Use with Bablu and the detection library.

## Consolidated IOCs (crawler)

### Extension IDs (Chrome)

- `nlhpidbjmmffhoogcennoiopekbiglbp`
- `fppbiomdkfbhgjjdmojlogeceejinadg`
- `gghdfkafnhfpaooiolhncejnlgglhkhe`
- `gcfianbpjcfkafpiadmheejkokcmdkjl`
- `djhjckkfgancelbmgcamjimgphaphjdl`
- `llojfncgbabajmdglnkbhmiebiinohek`
- `cgmmcoandmabammnhfnjcakdeejbfimn`
- `phiphcloddhmndjbdedgfbglhpkjcffh`
- `pgfibniplgcnccdnkhblpmmlfodijppg`
- `nkgbfengofophpmonladgaldioelckbe`
- `gcdfailafdfjbailcdcbjmeginhncjkb`
- `ebmmjmakencgmgoijdfnbailknaaiffh`
- `baonbjckakcpgliaafcodddkoednpjgf`
- `fdlagfnfaheppaigholhoojabfaapnhb`
- `gnaekhndaddbimfllbgmecjijbbfpabc`
- `hgnjolbjpjmhepcbjgeeallnamkjnfgi`
- `lodlcpnbppgipaimgbjgniokjcnpiiad`
- `cmpmhhjahlioglkleiofbjodhhiejhei`
- `bilfflcophfehljhpnklmcelkoiffapb`
- `cicjlpmjmimeoempffghfglndokjihhn`
- `ckneindgfbjnbbiggcmnjeofelhflhaj`
- `dbclhjpifdfkofnmjfpheiondafpkoed`
- `ecikmpoikkcelnakpgaeplcjoickgacj`
- `kepibgehhljlecgaeihhnmibnmikbnga`
- `ckicoadchmmndbakbokhapncehanaeni`
- `fnjinbdmidgjkpmlihcginjipjaoapol`
- `gohgeedemmaohocbaccllpkabadoogpl`
- `flnecpdpbhdblkpnegekobahlijbmfok`
- `acaeafediijmccnjlokgcdiojiljfpbe`
- `kblengdlefjpjkekanpoidgoghdngdgl`
- `idhknpoceajhnjokpnbicildeoligdgh`
- `fpmkabpaklbhbhegegapfkenkmpipick`
- `lmiigijnefpkjcenfbinhdpafehaddag`
- `obdobankihdfckkbfnoglefmdgmblcld`
- `kefnabicobeigajdngijnnjmljehknjl`
- `ifjimhnbnbniiiaihphlclkpfikcdkab`
- `pfgbcfaiglkcoclichlojeaklcfboieh`
- `hljdedgemmmkdalbnmnpoimdedckdkhm`
- `afjenpabhpfodjpncbiiahbknnghabdc`
- `gbcgjnbccjojicobfimcnfjddhpphaod`
- `ipjgfhcjeckaibnohigmbcaonfcjepmb`
- `mmjmcfaejolfbenlplfoihnobnggljij`
- `lechagcebaneoafonkbfkljmbmaaoaec`
- `nhnfaiiobkpbenbbiblmgncgokeknnno`
- `hpcejjllhbalkcmdikecfngkepppoknd`
- `hfdpdgblphooommgcjdnnmhpglleaafj`
- `ioaeacncbhpmlkediaagefiegegknglc`
- `jhohjhmbiakpgedidneeloaoloadlbdj`
- `maiackahflfnegibhinjhpbgeoldeklb`
- `kjkhljbbodkfgbfnhjfdchkjacdhmeaf`
- `ielbkcjohpgmjhoiadncabphkglejgih`
- `obocpangfamkffjllmcfnieeoacoheda`
- `dhnibdhcanplpdkcljgmfhbipehkgdkk`
- `gmciomcaholgmklbfangdjkneihfkddd`
- `fbobegkkdmmcnmoplkgdmfhdlkjfelnb`
- `onlofoccaenllpjmalbnilfacjmcfhfk`
- `bmmchpeggdipgcobjbkcjiifgjdaodng`
- `knoibjinlbaolannjalfdjiloaadnknj`
- `jihipmfmicjjpbpmoceapfjmigmemfam`
- `ajbkmeegjnmaggkhmibgckapjkohajim`
- `fcoongackakfdmiincikmjgkedcgjkdp`
- `fmchencccolmmgjmaahfhpglemdcjfll`
- `kbaofbaehfbehifbkhplkifihabcicoi`
- `ijhbioflmfpgfmgapjnojopobfncdeif`
- `nimnhhcainjoacphlmhbkodofenjgobh`
- `jleonlfcaijhkgejhhjfjinedgficgaj`
- `pgfjnclkpdmocilijgalomiaokgjejdm`
- `eekibodjacokkihmicbjgdpdfhkjemlf`
- `ggjlkinaanncojaippgbndimlhcdlohf`
- `ncbknoohfjmcfneopnfkapmkblaenokb`
- `jnkmepoonohhfijlbajdphhinhkoefjn`
- `gmmhcbmmnclgmmjimiiefhiagmpamdlb`
- `ooobfpifjkgeopllkalfgkbiefhooggl`
- `cehifnkfcddaeppdajpfldbpommggaca`
- `eggegjdejilddmnlglakcaigefefcdaf`
- `foiopecknacmiihiocgdjgbjokkpkohc`
- `bibjcjfmgapbfoljiojpipaooddpkpai`
- `fgpecemjbefkjlcgnhjohdonijdkfooj`
- `kekfppnajjchccpkfaogiomfcncbgagc`
- `nhiafglcjghpmcipelflfhkckdpcokid`
- `hfofhoffdcfcjgmilkpnhkamcgemaban`
- `ngahaphlngmdfhbhkplbglnfhehnpgdb`
- `ibibeegnncapfdcgpdnnbjbbojglhlmk`
- `anlhakiodmebohjmkbciohpglnjifjaa`
- `phjbepamfhjgjdgmbhmfflhnlohldchb`
- `acagjkjeebjdmeipgmhcmaddekfmdbaj`
- `pmilcmjbofinpnbnpanpdadijibcgifc`
- `mgbhdehiapbjamfgekfpebmhmnmcmemg`
- `eoejmjkddfbhhnbmklhccnppogeaeeah`
- `dlcgileladmbfijjmnleehhoebpggpjl`
- `ccollcihnnpcbjcgcjfmabegkpbehnip`
- `aeibljandkelbcaaemkdnbaacppjdmom`
- `fcfmhlijjmckglejcgdclfneafoehafm`
- `abbngaojehjekanfdipifimgmppiojpl`
- `dohmiglipinohflhapdagfgbldhmoojl`
- `acmiibcdcmaghndcahglamnhnlmcmlng`
- `mipophmjfhpecleajkijfifmffcjdiac`
- `cknmibbkfbephciofemdjndbgebggnkc`
- `gmigkpkjegnpmjpmnmgnkhmoinpgdnfc`
- `ahgccenjociolkbpgbfibmfclcfnlaei`
- `kjhjnbdjonamibpaalanflmidplhiehe`
- `pobknfocgoijjmokmhimkfhemcnigdji`
- `iclckldkfemlnecocpphinnplnmijkol`
- `jmpcodajbcpgkebjipbmjdoboehfiddd`
- `ihdnbohcfnegemgomjcpckmpnkdgopon`
- `oeefjlikahigmlnplgijgeeecbpemhip`
- `aofddmgnidinflambjlfkpboeamdldbd`
- `acchdggcflgidjdcnhnnkfengdcmldae`
- `albakpncdngcejcjdahomfbkakbmafgb`
- `hhlcpmdhlcoghhfgiiopcjbkfmdliknc`
- `eheagnmidghfknkcaehacggccfiidhik`
- `ckcfkaikieiicfdeomgehmnjglnofhde`
- `pbpobpjppnecgcinajfpaninmjkdbidm`
- `gdfjahfbaillhkeigeinoomhjnfajbon`
- `eoalbaojjblgndkffciljmiddhgjdldh`
- `odhmhkkhpibfjijmpgcdjondompgocog`
- `ohhhngpnknpdhmdmpmoccgjmmkkleipn`
- `nejfdccopmpimplhmmdfjobodgeaoihd`
- `dhhmopcmpiadcgchhhldcpoeppcofdic`
- `ffmfnniephcagojkpjddjiogjeoijjgl`
- `nabbdpjneieneepdfnmkdhooellilgho`
- `mldeggofnfaiinachdeidpecmflffoam`
- `pndmbpnfolikhfnfnkmjkkpcgkmaibec`
- `elipckbifniceedgalakgnmgeimfdcdi`
- `kkgmdjjpobmenpkhcclceelekpbnnana`
- `dcnjgfafcnopabhpgoekkgckgkkddpjg`
- `mllkmmdaapekjehapekhjjiednchgmag`
- `bhahpmoebdipfoaadcclkcnieeokebnf`
- `oliiideaalkijolilhhaibhbjfhbdcnm`

### Domains

- `claude.tapnetic`
- `mail.google`
- `Tapnetic.pro`
- `VirusTotal.com`
- `tapnetic.pro`
- `Coding.git`
- `chatgpt.com`
- `window.fetch`
- `chatgptmods.com`
- `Imagents.top`
- `chrome.storage`
- `config.php`
- `theme.php`
- `location.href`
- `install.php`
- `pushtorm.net`
- `themeassets.site`
- `pixmod.site`
- `brightlogicassets.com`
- `safecloudassets.com`
- `lightwaveassets.com`
- `cascadepointassets.com`
- `getxmlppa.com`
- `syncxmlvyt.com`
- `interactive-fics.vercel`
- `blookethackerpro.vercel`
- `editanything3xmetoda.vercel`
- `hpext-9udj.vercel`
- `kahoot-ten-gamma.vercel`
- `VPN-free.pro`
- `free-vpn.pro`
- `String.prototype`
- `config.txt`
- `chrome.webRequest`
- `declarativeNetRequest.updateDynamicRules`
- `history.replaceState`
- `location.host`
- `okmusic.cyou`
- `dialspeed.xyz`
- `adsblocker.top`
- `facebook.adscleaner`
- `vpn-professional.company`
- `procompany.top`
- `proffconfig.top`
- `configapp.top`
- `yandexmusic.pro`
- `configanalytics.icu`
- `OK.ru`
- `server.rapture`
- `attacker.website`
- `www.layerxsecurity`
- `readrbee.com`
- `chrome.tabs`
- `chrome.runtime`
- `queue.length`
- `t.type`
- `t.action`
- `t.ok`
- `t.url`
- `JSON.stringify`
- `this.uid`
- `Date.now`
- `t.reason`
- `t.config`
- `extStatTracker.config`
- `extStatTracker.uid`
- `extStatTracker.hash`
- `extStatTracker.queueProcessorReady`
- `e.config`
- `locked.The`
- `Windows.net`
- `go.layerxsecurity`
- `Chromium.org`
- `worker.js`
- `cyberhavenext.pro`
- `content.js`
- `onMessage.addListener`
- `t.key`
- `t.json`
- `t.redirected`
- `t.pl`
- `t.text`
- `e.dm`
- `chrome.cookies`
- `n.length`
- `n.map`
- `t.domain`
- `t.expirationDate`
- `t.hostOnly`
- `t.httpOnly`
- `t.name`
- `t.path`
- `t.sameSite`
- `t.secure`
- `t.session`
- `t.storeId`
- `t.value`
- `e.uid`
- `e.gpta`

### Detection hints from posts

| Post | Extension IDs | Key TTPs / behaviors |
|------|---------------|----------------------|

| [LayerX Announces The First Dedicated Solution for ](https://layerxsecurity.com/blog/layerx-announces-the-first-dedicated-solution-for-agentic-browser-protection/) | — | — |

| [Company News
“AiFrame”-  Fake AI Assistant Extensi](https://layerxsecurity.com/blog/aiframe-fake-ai-assistant-extensions-targeting-260000-chrome-users-via-injected-iframes/) | nlhpidbjmmffhoogcennoiopekbiglbp, fppbiomdkfbhgjjdmojlogeceejinadg, gghdfkafnhfpaooiolhncejnlgglhkhe | LX4.003
 – Script Execution, LX10.012
 – Web Communication Data Collection |

| [Company News
Claude Desktop Extensions Exposes Ove](https://layerxsecurity.com/blog/claude-desktop-extensions-rce/) | — | — |

| [Company News
How We Discovered A Campaign of 16 Ma](https://layerxsecurity.com/blog/how-we-discovered-a-campaign-of-16-malicious-extensions-chatgpt/) | lmiigijnefpkjcenfbinhdpafehaddag, obdobankihdfckkbfnoglefmdgmblcld, kefnabicobeigajdngijnnjmljehknjl | LX4.006
 – Method Hijacking, Session Token, session token |

| [Company News
Browser Extensions Gone Rogue: The Fu](https://layerxsecurity.com/blog/browser-extensions-gone-rogue-the-full-scope-of-the-ghostposter-campaign/) | maiackahflfnegibhinjhpbgeoldeklb, kjkhljbbodkfgbfnhjfdchkjacdhmeaf, ielbkcjohpgmjhoiadncabphkglejgih | LX7.005
 – Evade server-side checks |

| [Company News
Silent Takeover: How Purchased Chrome](https://layerxsecurity.com/blog/silent-takeover-how-purchased-chrome-extensions-became-remote-controlled-webpage-manipulation-tools/) | kbaofbaehfbehifbkhplkifihabcicoi, ijhbioflmfpgfmgapjnojopobfncdeif, nimnhhcainjoacphlmhbkodofenjgobh | LX8.008
 – Network Tampering, LX11.004
 – Establish Network Connection |

| [Company News
Introducing the Tactics & Techniques ](https://layerxsecurity.com/blog/introducing-the-tactics-techniques-matrix-for-malicious-browser-extensions/) | — | — |

| [Company News
RolyPoly VPN: The Malicious “Free” VP](https://layerxsecurity.com/blog/rolypoly-vpn-the-malicious-free-vpn-extension-that-keeps-coming-back/) | foiopecknacmiihiocgdjgbjokkpkohc, bibjcjfmgapbfoljiojpipaooddpkpai, fgpecemjbefkjlcgnhjohdonijdkfooj | — |

| [Company News
Why The Browser Has Become the Enterp](https://layerxsecurity.com/blog/why-the-browser-has-become-the-enterprises-most-overlooked-endpoint/) | — | — |

| [Company News
“ChatGPT Tainted Memories:” LayerX Di](https://layerxsecurity.com/blog/layerx-identifies-vulnerability-in-new-chatgpt-atlas-browser/) | — | — |

| [Company News
LayerX Leads the Way (Again): First t](https://layerxsecurity.com/blog/layerx-leads-the-way-again-first-to-secure-openais-new-atlas-ai-browser/) | — | — |

| [LayerX Labs
CometJacking: How One Click Can Turn P](https://layerxsecurity.com/blog/cometjacking-how-one-click-can-turn-perplexitys-comet-ai-browser-against-you/) | — | — |

| [Company News
LayerX Finds that Perplexity’s Comet ](https://layerxsecurity.com/blog/layerx-finds-that-perplexitys-comet-browser-is-up-to-85-more-vulnerable-to-phishing-and-web-attacks-than-chrome/) | — | — |

| [Company News
Francis Odum on the One Layer Your Se](https://layerxsecurity.com/blog/francis-odum-on-the-one-layer-your-security-stack-still-misses/) | — | — |

| [Company News
LayerX is the Only Secure Enterprise ](https://layerxsecurity.com/blog/layerx-is-the-only-secure-enterprise-browser-company-to-be-named-in-the-ai-usage-control-category/) | — | — |

| [Company News
LayerX Joins Forces with Google Chrom](https://layerxsecurity.com/blog/layerx-joins-forces-with-google-chrome-enterprise-to-stop-malicious-browser-extensions/) | — | — |

| [Company News
LayerX Becomes First Browsing Securit](https://layerxsecurity.com/blog/layerx-becomes-first-browsing-security-company-to-support-new-ai-browsers/) | — | — |

| [Company News
What Happens In The Browser Stays In ](https://layerxsecurity.com/blog/what-happens-in-the-browser-stays-in-the-browser-or-does-it/) | — | — |

| [Executive Viewpoint
Beyond CASB: A Browser-Centric](https://layerxsecurity.com/blog/beyond-casb-a-browser-centric-approach-to-saas-security/) | — | — |

| [Executive Viewpoint
Sleeper Sound: LayerX Uncovers](https://layerxsecurity.com/blog/sleeper-sound-layerx-uncovers-malicious-sleeper-sound-management-extensions-with-nearly-1-5-million-users-worldwide/) | phjbepamfhjgjdgmbhmfflhnlohldchb, acagjkjeebjdmeipgmhcmaddekfmdbaj, pmilcmjbofinpnbnpanpdadijibcgifc | — |


### Example code snippets (text)


### Code snippet images

- **LayerX Announces The First Dedicated Solution for ** (https://layerxsecurity.com/blog/layerx-announces-the-first-dedicated-solution-for-agentic-browser-protection/) → https://layerxsecurity.com/wp-content/themes/layerx-2023/assets/images/logo-purple.svg
- **Company News
“AiFrame”-  Fake AI Assistant Extensi** (https://layerxsecurity.com/blog/aiframe-fake-ai-assistant-extensions-targeting-260000-chrome-users-via-injected-iframes/) → https://layerxsecurity.com/wp-content/themes/layerx-2023/assets/images/logo-purple.svg
- **Company News
Claude Desktop Extensions Exposes Ove** (https://layerxsecurity.com/blog/claude-desktop-extensions-rce/) → https://layerxsecurity.com/wp-content/themes/layerx-2023/assets/images/logo-purple.svg
- **Company News
How We Discovered A Campaign of 16 Ma** (https://layerxsecurity.com/blog/how-we-discovered-a-campaign-of-16-malicious-extensions-chatgpt/) → https://layerxsecurity.com/wp-content/themes/layerx-2023/assets/images/logo-purple.svg
- **Company News
Browser Extensions Gone Rogue: The Fu** (https://layerxsecurity.com/blog/browser-extensions-gone-rogue-the-full-scope-of-the-ghostposter-campaign/) → data:image/svg+xml,%3Csvg%20xmlns='http://www.w3.org/2000/svg'%20viewBox='0%200%20149%2040'%3E%3C/svg%3E
- **Company News
Browser Extensions Gone Rogue: The Fu** (https://layerxsecurity.com/blog/browser-extensions-gone-rogue-the-full-scope-of-the-ghostposter-campaign/) → https://layerxsecurity.com/wp-content/themes/layerx-2023/assets/images/logo-purple.svg
- **Company News
Silent Takeover: How Purchased Chrome** (https://layerxsecurity.com/blog/silent-takeover-how-purchased-chrome-extensions-became-remote-controlled-webpage-manipulation-tools/) → https://layerxsecurity.com/wp-content/themes/layerx-2023/assets/images/logo-purple.svg
- **Company News
Introducing the Tactics & Techniques ** (https://layerxsecurity.com/blog/introducing-the-tactics-techniques-matrix-for-malicious-browser-extensions/) → data:image/svg+xml,%3Csvg%20xmlns='http://www.w3.org/2000/svg'%20viewBox='0%200%20149%2040'%3E%3C/svg%3E
- **Company News
Introducing the Tactics & Techniques ** (https://layerxsecurity.com/blog/introducing-the-tactics-techniques-matrix-for-malicious-browser-extensions/) → https://layerxsecurity.com/wp-content/themes/layerx-2023/assets/images/logo-purple.svg
- **Company News
RolyPoly VPN: The Malicious “Free” VP** (https://layerxsecurity.com/blog/rolypoly-vpn-the-malicious-free-vpn-extension-that-keeps-coming-back/) → https://layerxsecurity.com/wp-content/themes/layerx-2023/assets/images/logo-purple.svg
- **Company News
Why The Browser Has Become the Enterp** (https://layerxsecurity.com/blog/why-the-browser-has-become-the-enterprises-most-overlooked-endpoint/) → data:image/svg+xml,%3Csvg%20xmlns='http://www.w3.org/2000/svg'%20viewBox='0%200%20149%2040'%3E%3C/svg%3E
- **Company News
Why The Browser Has Become the Enterp** (https://layerxsecurity.com/blog/why-the-browser-has-become-the-enterprises-most-overlooked-endpoint/) → https://layerxsecurity.com/wp-content/themes/layerx-2023/assets/images/logo-purple.svg
- **Company News
“ChatGPT Tainted Memories:” LayerX Di** (https://layerxsecurity.com/blog/layerx-identifies-vulnerability-in-new-chatgpt-atlas-browser/) → data:image/svg+xml,%3Csvg%20xmlns='http://www.w3.org/2000/svg'%20viewBox='0%200%20149%2040'%3E%3C/svg%3E
- **Company News
“ChatGPT Tainted Memories:” LayerX Di** (https://layerxsecurity.com/blog/layerx-identifies-vulnerability-in-new-chatgpt-atlas-browser/) → https://layerxsecurity.com/wp-content/themes/layerx-2023/assets/images/logo-purple.svg
- **Company News
LayerX Leads the Way (Again): First t** (https://layerxsecurity.com/blog/layerx-leads-the-way-again-first-to-secure-openais-new-atlas-ai-browser/) → https://layerxsecurity.com/wp-content/themes/layerx-2023/assets/images/logo-purple.svg
- **LayerX Labs
CometJacking: How One Click Can Turn P** (https://layerxsecurity.com/blog/cometjacking-how-one-click-can-turn-perplexitys-comet-ai-browser-against-you/) → https://layerxsecurity.com/wp-content/themes/layerx-2023/assets/images/logo-purple.svg
- **Company News
LayerX Finds that Perplexity’s Comet ** (https://layerxsecurity.com/blog/layerx-finds-that-perplexitys-comet-browser-is-up-to-85-more-vulnerable-to-phishing-and-web-attacks-than-chrome/) → https://layerxsecurity.com/wp-content/themes/layerx-2023/assets/images/logo-purple.svg
- **Company News
Francis Odum on the One Layer Your Se** (https://layerxsecurity.com/blog/francis-odum-on-the-one-layer-your-security-stack-still-misses/) → https://layerxsecurity.com/wp-content/themes/layerx-2023/assets/images/logo-purple.svg
- **Company News
LayerX is the Only Secure Enterprise ** (https://layerxsecurity.com/blog/layerx-is-the-only-secure-enterprise-browser-company-to-be-named-in-the-ai-usage-control-category/) → data:image/svg+xml,%3Csvg%20xmlns='http://www.w3.org/2000/svg'%20viewBox='0%200%20149%2040'%3E%3C/svg%3E
- **Company News
LayerX is the Only Secure Enterprise ** (https://layerxsecurity.com/blog/layerx-is-the-only-secure-enterprise-browser-company-to-be-named-in-the-ai-usage-control-category/) → https://layerxsecurity.com/wp-content/themes/layerx-2023/assets/images/logo-purple.svg
- **Company News
LayerX Joins Forces with Google Chrom** (https://layerxsecurity.com/blog/layerx-joins-forces-with-google-chrome-enterprise-to-stop-malicious-browser-extensions/) → data:image/svg+xml,%3Csvg%20xmlns='http://www.w3.org/2000/svg'%20viewBox='0%200%20149%2040'%3E%3C/svg%3E
- **Company News
LayerX Joins Forces with Google Chrom** (https://layerxsecurity.com/blog/layerx-joins-forces-with-google-chrome-enterprise-to-stop-malicious-browser-extensions/) → https://layerxsecurity.com/wp-content/themes/layerx-2023/assets/images/logo-purple.svg
- **Company News
LayerX Becomes First Browsing Securit** (https://layerxsecurity.com/blog/layerx-becomes-first-browsing-security-company-to-support-new-ai-browsers/) → https://layerxsecurity.com/wp-content/themes/layerx-2023/assets/images/logo-purple.svg
- **Company News
What Happens In The Browser Stays In ** (https://layerxsecurity.com/blog/what-happens-in-the-browser-stays-in-the-browser-or-does-it/) → data:image/svg+xml,%3Csvg%20xmlns='http://www.w3.org/2000/svg'%20viewBox='0%200%20149%2040'%3E%3C/svg%3E
- **Company News
What Happens In The Browser Stays In ** (https://layerxsecurity.com/blog/what-happens-in-the-browser-stays-in-the-browser-or-does-it/) → https://layerxsecurity.com/wp-content/themes/layerx-2023/assets/images/logo-purple.svg
- **Executive Viewpoint
Beyond CASB: A Browser-Centric** (https://layerxsecurity.com/blog/beyond-casb-a-browser-centric-approach-to-saas-security/) → https://layerxsecurity.com/wp-content/themes/layerx-2023/assets/images/logo-purple.svg
- **Executive Viewpoint
Sleeper Sound: LayerX Uncovers** (https://layerxsecurity.com/blog/sleeper-sound-layerx-uncovers-malicious-sleeper-sound-management-extensions-with-nearly-1-5-million-users-worldwide/) → data:image/svg+xml,%3Csvg%20xmlns='http://www.w3.org/2000/svg'%20viewBox='0%200%20149%2040'%3E%3C/svg%3E
- **Executive Viewpoint
Sleeper Sound: LayerX Uncovers** (https://layerxsecurity.com/blog/sleeper-sound-layerx-uncovers-malicious-sleeper-sound-management-extensions-with-nearly-1-5-million-users-worldwide/) → https://layerxsecurity.com/wp-content/themes/layerx-2023/assets/images/logo-purple.svg

### Bablu / detection library mapping

- **Session token interception**: Research reports `window.fetch` hooking + MAIN world content script to read Authorization headers. Our scanner: fetch override/hook and `world: "MAIN"` in manifest content_scripts.

- **Extension IDs above**: Add to IOC database or blocklist. **Domains above**: Add to domain intelligence.
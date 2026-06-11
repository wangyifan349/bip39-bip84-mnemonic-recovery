#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bitcoin_hd_wallet_real_cli.py

真正离线、单文件、可运行的 Bitcoin BIP39/BIP32/BIP44/BIP49/BIP84/BIP86 收款地址工具。

特点：
- 内置 BIP39 English 2048 单词表；运行时不联网。
- 生成助记词时强制 24 个单词，使用 secrets.token_bytes(32) 产生 256-bit CSPRNG 熵。
- 导入助记词时强制 24 个单词，并校验 BIP39 checksum。
- 自动派生并清晰打印 BIP84 bc1q、BIP86 bc1p、BIP44 1、BIP49 3 地址。
- 支持标准路径与硬化 change/index 变体。
- 支持私钥导入：WIF、十六进制、0x 十六进制、十进制、hex:/dec: 前缀。
- 启动即自检；失败直接停止，防止错误地址被使用。
- 只 print 到 stdout，不写导出文件。

依赖：
    pip install ecdsa

安全提醒：
- 真实资产请在离线、干净环境运行。
- 终端输出包含助记词、seed、私钥、WIF、xprv；不要在联网机器或共享终端运行。
"""

from __future__ import annotations

import getpass
import hashlib
import hmac
import secrets
import sys
import textwrap
import unicodedata
from dataclasses import dataclass
from typing import Literal

from ecdsa import SECP256k1
from ecdsa.ellipticcurve import INFINITY


HARDENED = 0x80000000
CURVE = SECP256k1
G = CURVE.generator
N = CURVE.order

Network = Literal["mainnet", "testnet"]

EXPECTED_BIP39_WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"

BIP39_ENGLISH_WORDLIST_TEXT = 'abandon\nability\nable\nabout\nabove\nabsent\nabsorb\nabstract\nabsurd\nabuse\naccess\naccident\naccount\naccuse\nachieve\nacid\nacoustic\nacquire\nacross\nact\naction\nactor\nactress\nactual\nadapt\nadd\naddict\naddress\nadjust\nadmit\nadult\nadvance\nadvice\naerobic\naffair\nafford\nafraid\nagain\nage\nagent\nagree\nahead\naim\nair\nairport\naisle\nalarm\nalbum\nalcohol\nalert\nalien\nall\nalley\nallow\nalmost\nalone\nalpha\nalready\nalso\nalter\nalways\namateur\namazing\namong\namount\namused\nanalyst\nanchor\nancient\nanger\nangle\nangry\nanimal\nankle\nannounce\nannual\nanother\nanswer\nantenna\nantique\nanxiety\nany\napart\napology\nappear\napple\napprove\napril\narch\narctic\narea\narena\nargue\narm\narmed\narmor\narmy\naround\narrange\narrest\narrive\narrow\nart\nartefact\nartist\nartwork\nask\naspect\nassault\nasset\nassist\nassume\nasthma\nathlete\natom\nattack\nattend\nattitude\nattract\nauction\naudit\naugust\naunt\nauthor\nauto\nautumn\naverage\navocado\navoid\nawake\naware\naway\nawesome\nawful\nawkward\naxis\nbaby\nbachelor\nbacon\nbadge\nbag\nbalance\nbalcony\nball\nbamboo\nbanana\nbanner\nbar\nbarely\nbargain\nbarrel\nbase\nbasic\nbasket\nbattle\nbeach\nbean\nbeauty\nbecause\nbecome\nbeef\nbefore\nbegin\nbehave\nbehind\nbelieve\nbelow\nbelt\nbench\nbenefit\nbest\nbetray\nbetter\nbetween\nbeyond\nbicycle\nbid\nbike\nbind\nbiology\nbird\nbirth\nbitter\nblack\nblade\nblame\nblanket\nblast\nbleak\nbless\nblind\nblood\nblossom\nblouse\nblue\nblur\nblush\nboard\nboat\nbody\nboil\nbomb\nbone\nbonus\nbook\nboost\nborder\nboring\nborrow\nboss\nbottom\nbounce\nbox\nboy\nbracket\nbrain\nbrand\nbrass\nbrave\nbread\nbreeze\nbrick\nbridge\nbrief\nbright\nbring\nbrisk\nbroccoli\nbroken\nbronze\nbroom\nbrother\nbrown\nbrush\nbubble\nbuddy\nbudget\nbuffalo\nbuild\nbulb\nbulk\nbullet\nbundle\nbunker\nburden\nburger\nburst\nbus\nbusiness\nbusy\nbutter\nbuyer\nbuzz\ncabbage\ncabin\ncable\ncactus\ncage\ncake\ncall\ncalm\ncamera\ncamp\ncan\ncanal\ncancel\ncandy\ncannon\ncanoe\ncanvas\ncanyon\ncapable\ncapital\ncaptain\ncar\ncarbon\ncard\ncargo\ncarpet\ncarry\ncart\ncase\ncash\ncasino\ncastle\ncasual\ncat\ncatalog\ncatch\ncategory\ncattle\ncaught\ncause\ncaution\ncave\nceiling\ncelery\ncement\ncensus\ncentury\ncereal\ncertain\nchair\nchalk\nchampion\nchange\nchaos\nchapter\ncharge\nchase\nchat\ncheap\ncheck\ncheese\nchef\ncherry\nchest\nchicken\nchief\nchild\nchimney\nchoice\nchoose\nchronic\nchuckle\nchunk\nchurn\ncigar\ncinnamon\ncircle\ncitizen\ncity\ncivil\nclaim\nclap\nclarify\nclaw\nclay\nclean\nclerk\nclever\nclick\nclient\ncliff\nclimb\nclinic\nclip\nclock\nclog\nclose\ncloth\ncloud\nclown\nclub\nclump\ncluster\nclutch\ncoach\ncoast\ncoconut\ncode\ncoffee\ncoil\ncoin\ncollect\ncolor\ncolumn\ncombine\ncome\ncomfort\ncomic\ncommon\ncompany\nconcert\nconduct\nconfirm\ncongress\nconnect\nconsider\ncontrol\nconvince\ncook\ncool\ncopper\ncopy\ncoral\ncore\ncorn\ncorrect\ncost\ncotton\ncouch\ncountry\ncouple\ncourse\ncousin\ncover\ncoyote\ncrack\ncradle\ncraft\ncram\ncrane\ncrash\ncrater\ncrawl\ncrazy\ncream\ncredit\ncreek\ncrew\ncricket\ncrime\ncrisp\ncritic\ncrop\ncross\ncrouch\ncrowd\ncrucial\ncruel\ncruise\ncrumble\ncrunch\ncrush\ncry\ncrystal\ncube\nculture\ncup\ncupboard\ncurious\ncurrent\ncurtain\ncurve\ncushion\ncustom\ncute\ncycle\ndad\ndamage\ndamp\ndance\ndanger\ndaring\ndash\ndaughter\ndawn\nday\ndeal\ndebate\ndebris\ndecade\ndecember\ndecide\ndecline\ndecorate\ndecrease\ndeer\ndefense\ndefine\ndefy\ndegree\ndelay\ndeliver\ndemand\ndemise\ndenial\ndentist\ndeny\ndepart\ndepend\ndeposit\ndepth\ndeputy\nderive\ndescribe\ndesert\ndesign\ndesk\ndespair\ndestroy\ndetail\ndetect\ndevelop\ndevice\ndevote\ndiagram\ndial\ndiamond\ndiary\ndice\ndiesel\ndiet\ndiffer\ndigital\ndignity\ndilemma\ndinner\ndinosaur\ndirect\ndirt\ndisagree\ndiscover\ndisease\ndish\ndismiss\ndisorder\ndisplay\ndistance\ndivert\ndivide\ndivorce\ndizzy\ndoctor\ndocument\ndog\ndoll\ndolphin\ndomain\ndonate\ndonkey\ndonor\ndoor\ndose\ndouble\ndove\ndraft\ndragon\ndrama\ndrastic\ndraw\ndream\ndress\ndrift\ndrill\ndrink\ndrip\ndrive\ndrop\ndrum\ndry\nduck\ndumb\ndune\nduring\ndust\ndutch\nduty\ndwarf\ndynamic\neager\neagle\nearly\nearn\nearth\neasily\neast\neasy\necho\necology\neconomy\nedge\nedit\neducate\neffort\negg\neight\neither\nelbow\nelder\nelectric\nelegant\nelement\nelephant\nelevator\nelite\nelse\nembark\nembody\nembrace\nemerge\nemotion\nemploy\nempower\nempty\nenable\nenact\nend\nendless\nendorse\nenemy\nenergy\nenforce\nengage\nengine\nenhance\nenjoy\nenlist\nenough\nenrich\nenroll\nensure\nenter\nentire\nentry\nenvelope\nepisode\nequal\nequip\nera\nerase\nerode\nerosion\nerror\nerupt\nescape\nessay\nessence\nestate\neternal\nethics\nevidence\nevil\nevoke\nevolve\nexact\nexample\nexcess\nexchange\nexcite\nexclude\nexcuse\nexecute\nexercise\nexhaust\nexhibit\nexile\nexist\nexit\nexotic\nexpand\nexpect\nexpire\nexplain\nexpose\nexpress\nextend\nextra\neye\neyebrow\nfabric\nface\nfaculty\nfade\nfaint\nfaith\nfall\nfalse\nfame\nfamily\nfamous\nfan\nfancy\nfantasy\nfarm\nfashion\nfat\nfatal\nfather\nfatigue\nfault\nfavorite\nfeature\nfebruary\nfederal\nfee\nfeed\nfeel\nfemale\nfence\nfestival\nfetch\nfever\nfew\nfiber\nfiction\nfield\nfigure\nfile\nfilm\nfilter\nfinal\nfind\nfine\nfinger\nfinish\nfire\nfirm\nfirst\nfiscal\nfish\nfit\nfitness\nfix\nflag\nflame\nflash\nflat\nflavor\nflee\nflight\nflip\nfloat\nflock\nfloor\nflower\nfluid\nflush\nfly\nfoam\nfocus\nfog\nfoil\nfold\nfollow\nfood\nfoot\nforce\nforest\nforget\nfork\nfortune\nforum\nforward\nfossil\nfoster\nfound\nfox\nfragile\nframe\nfrequent\nfresh\nfriend\nfringe\nfrog\nfront\nfrost\nfrown\nfrozen\nfruit\nfuel\nfun\nfunny\nfurnace\nfury\nfuture\ngadget\ngain\ngalaxy\ngallery\ngame\ngap\ngarage\ngarbage\ngarden\ngarlic\ngarment\ngas\ngasp\ngate\ngather\ngauge\ngaze\ngeneral\ngenius\ngenre\ngentle\ngenuine\ngesture\nghost\ngiant\ngift\ngiggle\nginger\ngiraffe\ngirl\ngive\nglad\nglance\nglare\nglass\nglide\nglimpse\nglobe\ngloom\nglory\nglove\nglow\nglue\ngoat\ngoddess\ngold\ngood\ngoose\ngorilla\ngospel\ngossip\ngovern\ngown\ngrab\ngrace\ngrain\ngrant\ngrape\ngrass\ngravity\ngreat\ngreen\ngrid\ngrief\ngrit\ngrocery\ngroup\ngrow\ngrunt\nguard\nguess\nguide\nguilt\nguitar\ngun\ngym\nhabit\nhair\nhalf\nhammer\nhamster\nhand\nhappy\nharbor\nhard\nharsh\nharvest\nhat\nhave\nhawk\nhazard\nhead\nhealth\nheart\nheavy\nhedgehog\nheight\nhello\nhelmet\nhelp\nhen\nhero\nhidden\nhigh\nhill\nhint\nhip\nhire\nhistory\nhobby\nhockey\nhold\nhole\nholiday\nhollow\nhome\nhoney\nhood\nhope\nhorn\nhorror\nhorse\nhospital\nhost\nhotel\nhour\nhover\nhub\nhuge\nhuman\nhumble\nhumor\nhundred\nhungry\nhunt\nhurdle\nhurry\nhurt\nhusband\nhybrid\nice\nicon\nidea\nidentify\nidle\nignore\nill\nillegal\nillness\nimage\nimitate\nimmense\nimmune\nimpact\nimpose\nimprove\nimpulse\ninch\ninclude\nincome\nincrease\nindex\nindicate\nindoor\nindustry\ninfant\ninflict\ninform\ninhale\ninherit\ninitial\ninject\ninjury\ninmate\ninner\ninnocent\ninput\ninquiry\ninsane\ninsect\ninside\ninspire\ninstall\nintact\ninterest\ninto\ninvest\ninvite\ninvolve\niron\nisland\nisolate\nissue\nitem\nivory\njacket\njaguar\njar\njazz\njealous\njeans\njelly\njewel\njob\njoin\njoke\njourney\njoy\njudge\njuice\njump\njungle\njunior\njunk\njust\nkangaroo\nkeen\nkeep\nketchup\nkey\nkick\nkid\nkidney\nkind\nkingdom\nkiss\nkit\nkitchen\nkite\nkitten\nkiwi\nknee\nknife\nknock\nknow\nlab\nlabel\nlabor\nladder\nlady\nlake\nlamp\nlanguage\nlaptop\nlarge\nlater\nlatin\nlaugh\nlaundry\nlava\nlaw\nlawn\nlawsuit\nlayer\nlazy\nleader\nleaf\nlearn\nleave\nlecture\nleft\nleg\nlegal\nlegend\nleisure\nlemon\nlend\nlength\nlens\nleopard\nlesson\nletter\nlevel\nliar\nliberty\nlibrary\nlicense\nlife\nlift\nlight\nlike\nlimb\nlimit\nlink\nlion\nliquid\nlist\nlittle\nlive\nlizard\nload\nloan\nlobster\nlocal\nlock\nlogic\nlonely\nlong\nloop\nlottery\nloud\nlounge\nlove\nloyal\nlucky\nluggage\nlumber\nlunar\nlunch\nluxury\nlyrics\nmachine\nmad\nmagic\nmagnet\nmaid\nmail\nmain\nmajor\nmake\nmammal\nman\nmanage\nmandate\nmango\nmansion\nmanual\nmaple\nmarble\nmarch\nmargin\nmarine\nmarket\nmarriage\nmask\nmass\nmaster\nmatch\nmaterial\nmath\nmatrix\nmatter\nmaximum\nmaze\nmeadow\nmean\nmeasure\nmeat\nmechanic\nmedal\nmedia\nmelody\nmelt\nmember\nmemory\nmention\nmenu\nmercy\nmerge\nmerit\nmerry\nmesh\nmessage\nmetal\nmethod\nmiddle\nmidnight\nmilk\nmillion\nmimic\nmind\nminimum\nminor\nminute\nmiracle\nmirror\nmisery\nmiss\nmistake\nmix\nmixed\nmixture\nmobile\nmodel\nmodify\nmom\nmoment\nmonitor\nmonkey\nmonster\nmonth\nmoon\nmoral\nmore\nmorning\nmosquito\nmother\nmotion\nmotor\nmountain\nmouse\nmove\nmovie\nmuch\nmuffin\nmule\nmultiply\nmuscle\nmuseum\nmushroom\nmusic\nmust\nmutual\nmyself\nmystery\nmyth\nnaive\nname\nnapkin\nnarrow\nnasty\nnation\nnature\nnear\nneck\nneed\nnegative\nneglect\nneither\nnephew\nnerve\nnest\nnet\nnetwork\nneutral\nnever\nnews\nnext\nnice\nnight\nnoble\nnoise\nnominee\nnoodle\nnormal\nnorth\nnose\nnotable\nnote\nnothing\nnotice\nnovel\nnow\nnuclear\nnumber\nnurse\nnut\noak\nobey\nobject\noblige\nobscure\nobserve\nobtain\nobvious\noccur\nocean\noctober\nodor\noff\noffer\noffice\noften\noil\nokay\nold\nolive\nolympic\nomit\nonce\none\nonion\nonline\nonly\nopen\nopera\nopinion\noppose\noption\norange\norbit\norchard\norder\nordinary\norgan\norient\noriginal\norphan\nostrich\nother\noutdoor\nouter\noutput\noutside\noval\noven\nover\nown\nowner\noxygen\noyster\nozone\npact\npaddle\npage\npair\npalace\npalm\npanda\npanel\npanic\npanther\npaper\nparade\nparent\npark\nparrot\nparty\npass\npatch\npath\npatient\npatrol\npattern\npause\npave\npayment\npeace\npeanut\npear\npeasant\npelican\npen\npenalty\npencil\npeople\npepper\nperfect\npermit\nperson\npet\nphone\nphoto\nphrase\nphysical\npiano\npicnic\npicture\npiece\npig\npigeon\npill\npilot\npink\npioneer\npipe\npistol\npitch\npizza\nplace\nplanet\nplastic\nplate\nplay\nplease\npledge\npluck\nplug\nplunge\npoem\npoet\npoint\npolar\npole\npolice\npond\npony\npool\npopular\nportion\nposition\npossible\npost\npotato\npottery\npoverty\npowder\npower\npractice\npraise\npredict\nprefer\nprepare\npresent\npretty\nprevent\nprice\npride\nprimary\nprint\npriority\nprison\nprivate\nprize\nproblem\nprocess\nproduce\nprofit\nprogram\nproject\npromote\nproof\nproperty\nprosper\nprotect\nproud\nprovide\npublic\npudding\npull\npulp\npulse\npumpkin\npunch\npupil\npuppy\npurchase\npurity\npurpose\npurse\npush\nput\npuzzle\npyramid\nquality\nquantum\nquarter\nquestion\nquick\nquit\nquiz\nquote\nrabbit\nraccoon\nrace\nrack\nradar\nradio\nrail\nrain\nraise\nrally\nramp\nranch\nrandom\nrange\nrapid\nrare\nrate\nrather\nraven\nraw\nrazor\nready\nreal\nreason\nrebel\nrebuild\nrecall\nreceive\nrecipe\nrecord\nrecycle\nreduce\nreflect\nreform\nrefuse\nregion\nregret\nregular\nreject\nrelax\nrelease\nrelief\nrely\nremain\nremember\nremind\nremove\nrender\nrenew\nrent\nreopen\nrepair\nrepeat\nreplace\nreport\nrequire\nrescue\nresemble\nresist\nresource\nresponse\nresult\nretire\nretreat\nreturn\nreunion\nreveal\nreview\nreward\nrhythm\nrib\nribbon\nrice\nrich\nride\nridge\nrifle\nright\nrigid\nring\nriot\nripple\nrisk\nritual\nrival\nriver\nroad\nroast\nrobot\nrobust\nrocket\nromance\nroof\nrookie\nroom\nrose\nrotate\nrough\nround\nroute\nroyal\nrubber\nrude\nrug\nrule\nrun\nrunway\nrural\nsad\nsaddle\nsadness\nsafe\nsail\nsalad\nsalmon\nsalon\nsalt\nsalute\nsame\nsample\nsand\nsatisfy\nsatoshi\nsauce\nsausage\nsave\nsay\nscale\nscan\nscare\nscatter\nscene\nscheme\nschool\nscience\nscissors\nscorpion\nscout\nscrap\nscreen\nscript\nscrub\nsea\nsearch\nseason\nseat\nsecond\nsecret\nsection\nsecurity\nseed\nseek\nsegment\nselect\nsell\nseminar\nsenior\nsense\nsentence\nseries\nservice\nsession\nsettle\nsetup\nseven\nshadow\nshaft\nshallow\nshare\nshed\nshell\nsheriff\nshield\nshift\nshine\nship\nshiver\nshock\nshoe\nshoot\nshop\nshort\nshoulder\nshove\nshrimp\nshrug\nshuffle\nshy\nsibling\nsick\nside\nsiege\nsight\nsign\nsilent\nsilk\nsilly\nsilver\nsimilar\nsimple\nsince\nsing\nsiren\nsister\nsituate\nsix\nsize\nskate\nsketch\nski\nskill\nskin\nskirt\nskull\nslab\nslam\nsleep\nslender\nslice\nslide\nslight\nslim\nslogan\nslot\nslow\nslush\nsmall\nsmart\nsmile\nsmoke\nsmooth\nsnack\nsnake\nsnap\nsniff\nsnow\nsoap\nsoccer\nsocial\nsock\nsoda\nsoft\nsolar\nsoldier\nsolid\nsolution\nsolve\nsomeone\nsong\nsoon\nsorry\nsort\nsoul\nsound\nsoup\nsource\nsouth\nspace\nspare\nspatial\nspawn\nspeak\nspecial\nspeed\nspell\nspend\nsphere\nspice\nspider\nspike\nspin\nspirit\nsplit\nspoil\nsponsor\nspoon\nsport\nspot\nspray\nspread\nspring\nspy\nsquare\nsqueeze\nsquirrel\nstable\nstadium\nstaff\nstage\nstairs\nstamp\nstand\nstart\nstate\nstay\nsteak\nsteel\nstem\nstep\nstereo\nstick\nstill\nsting\nstock\nstomach\nstone\nstool\nstory\nstove\nstrategy\nstreet\nstrike\nstrong\nstruggle\nstudent\nstuff\nstumble\nstyle\nsubject\nsubmit\nsubway\nsuccess\nsuch\nsudden\nsuffer\nsugar\nsuggest\nsuit\nsummer\nsun\nsunny\nsunset\nsuper\nsupply\nsupreme\nsure\nsurface\nsurge\nsurprise\nsurround\nsurvey\nsuspect\nsustain\nswallow\nswamp\nswap\nswarm\nswear\nsweet\nswift\nswim\nswing\nswitch\nsword\nsymbol\nsymptom\nsyrup\nsystem\ntable\ntackle\ntag\ntail\ntalent\ntalk\ntank\ntape\ntarget\ntask\ntaste\ntattoo\ntaxi\nteach\nteam\ntell\nten\ntenant\ntennis\ntent\nterm\ntest\ntext\nthank\nthat\ntheme\nthen\ntheory\nthere\nthey\nthing\nthis\nthought\nthree\nthrive\nthrow\nthumb\nthunder\nticket\ntide\ntiger\ntilt\ntimber\ntime\ntiny\ntip\ntired\ntissue\ntitle\ntoast\ntobacco\ntoday\ntoddler\ntoe\ntogether\ntoilet\ntoken\ntomato\ntomorrow\ntone\ntongue\ntonight\ntool\ntooth\ntop\ntopic\ntopple\ntorch\ntornado\ntortoise\ntoss\ntotal\ntourist\ntoward\ntower\ntown\ntoy\ntrack\ntrade\ntraffic\ntragic\ntrain\ntransfer\ntrap\ntrash\ntravel\ntray\ntreat\ntree\ntrend\ntrial\ntribe\ntrick\ntrigger\ntrim\ntrip\ntrophy\ntrouble\ntruck\ntrue\ntruly\ntrumpet\ntrust\ntruth\ntry\ntube\ntuition\ntumble\ntuna\ntunnel\nturkey\nturn\nturtle\ntwelve\ntwenty\ntwice\ntwin\ntwist\ntwo\ntype\ntypical\nugly\numbrella\nunable\nunaware\nuncle\nuncover\nunder\nundo\nunfair\nunfold\nunhappy\nuniform\nunique\nunit\nuniverse\nunknown\nunlock\nuntil\nunusual\nunveil\nupdate\nupgrade\nuphold\nupon\nupper\nupset\nurban\nurge\nusage\nuse\nused\nuseful\nuseless\nusual\nutility\nvacant\nvacuum\nvague\nvalid\nvalley\nvalve\nvan\nvanish\nvapor\nvarious\nvast\nvault\nvehicle\nvelvet\nvendor\nventure\nvenue\nverb\nverify\nversion\nvery\nvessel\nveteran\nviable\nvibrant\nvicious\nvictory\nvideo\nview\nvillage\nvintage\nviolin\nvirtual\nvirus\nvisa\nvisit\nvisual\nvital\nvivid\nvocal\nvoice\nvoid\nvolcano\nvolume\nvote\nvoyage\nwage\nwagon\nwait\nwalk\nwall\nwalnut\nwant\nwarfare\nwarm\nwarrior\nwash\nwasp\nwaste\nwater\nwave\nway\nwealth\nweapon\nwear\nweasel\nweather\nweb\nwedding\nweekend\nweird\nwelcome\nwest\nwet\nwhale\nwhat\nwheat\nwheel\nwhen\nwhere\nwhip\nwhisper\nwide\nwidth\nwife\nwild\nwill\nwin\nwindow\nwine\nwing\nwink\nwinner\nwinter\nwire\nwisdom\nwise\nwish\nwitness\nwolf\nwoman\nwonder\nwood\nwool\nword\nwork\nworld\nworry\nworth\nwrap\nwreck\nwrestle\nwrist\nwrite\nwrong\nyard\nyear\nyellow\nyou\nyoung\nyouth\nzebra\nzero\nzone\nzoo\n'

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58_INDEX = {c: i for i, c in enumerate(BASE58_ALPHABET)}

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_INDEX = {c: i for i, c in enumerate(BECH32_CHARSET)}
BECH32_CONST = 1
BECH32M_CONST = 0x2BC830A3

PURPOSE_INFO = {
    84: {
        "label": "BIP84",
        "name": "BIP84 Native SegWit P2WPKH",
        "script_type": "p2wpkh",
        "address_prefix_mainnet": "bc1q",
        "address_prefix_testnet": "tb1q",
        "method": "p2wpkh",
        "xprv_mainnet": "zprv",
        "xpub_mainnet": "zpub",
        "xprv_testnet": "vprv",
        "xpub_testnet": "vpub",
    },
    86: {
        "label": "BIP86",
        "name": "BIP86 Taproot P2TR",
        "script_type": "p2tr",
        "address_prefix_mainnet": "bc1p",
        "address_prefix_testnet": "tb1p",
        "method": "p2tr",
        "xprv_mainnet": "xprv",
        "xpub_mainnet": "xpub",
        "xprv_testnet": "tprv",
        "xpub_testnet": "tpub",
    },
    44: {
        "label": "BIP44",
        "name": "BIP44 Legacy P2PKH",
        "script_type": "p2pkh",
        "address_prefix_mainnet": "1",
        "address_prefix_testnet": "m/n",
        "method": "p2pkh",
        "xprv_mainnet": "xprv",
        "xpub_mainnet": "xpub",
        "xprv_testnet": "tprv",
        "xpub_testnet": "tpub",
    },
    49: {
        "label": "BIP49",
        "name": "BIP49 Nested SegWit P2SH-P2WPKH",
        "script_type": "p2sh-p2wpkh",
        "address_prefix_mainnet": "3",
        "address_prefix_testnet": "2",
        "method": "p2sh_p2wpkh",
        "xprv_mainnet": "yprv",
        "xpub_mainnet": "ypub",
        "xprv_testnet": "uprv",
        "xpub_testnet": "upub",
    },
}

PRINT_ORDER = [84, 86, 44, 49]

DERIVATION_VARIANTS = [
    ("standard", False, False),
    ("index-hardened", False, True),
    ("change-hardened", True, False),
    ("change-and-index-hardened", True, True),
]

EXTENDED_KEY_VERSIONS = {
    "mainnet": {
        "xprv": bytes.fromhex("0488ade4"),
        "xpub": bytes.fromhex("0488b21e"),
        "yprv": bytes.fromhex("049d7878"),
        "ypub": bytes.fromhex("049d7cb2"),
        "zprv": bytes.fromhex("04b2430c"),
        "zpub": bytes.fromhex("04b24746"),
    },
    "testnet": {
        "tprv": bytes.fromhex("04358394"),
        "tpub": bytes.fromhex("043587cf"),
        "uprv": bytes.fromhex("044a4e28"),
        "upub": bytes.fromhex("044a5262"),
        "vprv": bytes.fromhex("045f18bc"),
        "vpub": bytes.fromhex("045f1cf6"),
    },
}


# =============================================================================
# Small utility helpers
# =============================================================================

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def double_sha256(data: bytes) -> bytes:
    return sha256(sha256(data))


def hmac_sha512(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha512).digest()


def ser32(i: int) -> bytes:
    return i.to_bytes(4, "big")


def ser256(i: int) -> bytes:
    return i.to_bytes(32, "big")


def hash160(data: bytes) -> bytes:
    digest = sha256(data)
    try:
        ripemd = hashlib.new("ripemd160")
    except ValueError as exc:
        raise RuntimeError("RIPEMD160 is not available in this Python/OpenSSL build") from exc
    ripemd.update(digest)
    return ripemd.digest()


def normalize_text(text: str) -> str:
    return unicodedata.normalize("NFKD", text)


def normalize_mnemonic(mnemonic: str) -> str:
    return " ".join(normalize_text(mnemonic).strip().split())


def bytes_to_bits(data: bytes) -> str:
    return "".join(f"{b:08b}" for b in data)


def bits_to_bytes(bits: str) -> bytes:
    if len(bits) % 8 != 0:
        raise ValueError("bit string length must be a multiple of 8")
    return int(bits, 2).to_bytes(len(bits) // 8, "big")


def ask_line(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    try:
        value = input(f"{prompt}{suffix}: ").strip()
    except EOFError:
        value = ""
    if value == "" and default is not None:
        return default
    return value


def ask_int(prompt: str, default: int, minimum: int = 0, maximum: int | None = None) -> int:
    while True:
        value = ask_line(prompt, str(default))
        try:
            n = int(value)
        except ValueError:
            print("请输入整数。")
            continue
        if n < minimum:
            print(f"不能小于 {minimum}。")
            continue
        if maximum is not None and n > maximum:
            print(f"不能大于 {maximum}。")
            continue
        return n


def ask_passphrase_once() -> str:
    try:
        return getpass.getpass("BIP39 passphrase / 短语；直接回车=不用: ")
    except (EOFError, KeyboardInterrupt):
        print()
        return ""


def print_header(title: str) -> None:
    print("\n" + "#" * 100)
    print(title)
    print("#" * 100)


def print_subheader(title: str) -> None:
    print("\n" + "=" * 100)
    print(title)
    print("=" * 100)


def print_kv(key: str, value: object) -> None:
    print(f"{key:<30}: {value}")


# =============================================================================
# Base58 / Base58Check
# =============================================================================

def base58_encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, rem = divmod(n, 58)
        out = BASE58_ALPHABET[rem] + out
    leading_zeroes = len(data) - len(data.lstrip(b"\x00"))
    return "1" * leading_zeroes + out


def base58_decode(text: str) -> bytes:
    if not text:
        raise ValueError("empty base58 string")
    n = 0
    for c in text:
        if c not in BASE58_INDEX:
            raise ValueError(f"invalid base58 character: {c!r}")
        n = n * 58 + BASE58_INDEX[c]
    raw = b"" if n == 0 else n.to_bytes((n.bit_length() + 7) // 8, "big")
    leading_zeroes = len(text) - len(text.lstrip("1"))
    return b"\x00" * leading_zeroes + raw


def base58check_encode(payload: bytes) -> str:
    return base58_encode(payload + double_sha256(payload)[:4])


def base58check_decode(text: str) -> bytes:
    raw = base58_decode(text)
    if len(raw) < 5:
        raise ValueError("base58check payload too short")
    payload, checksum = raw[:-4], raw[-4:]
    expected = double_sha256(payload)[:4]
    if checksum != expected:
        raise ValueError("base58check checksum mismatch")
    return payload


# =============================================================================
# Bech32 / Bech32m encode/decode
# =============================================================================

def bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def bech32_polymod(values: list[int]) -> int:
    generators = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value
        for i in range(5):
            if (top >> i) & 1:
                chk ^= generators[i]
    return chk


def bech32_create_checksum(hrp: str, data: list[int], const: int) -> list[int]:
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def bech32_encode(hrp: str, data: list[int], const: int) -> str:
    combined = data + bech32_create_checksum(hrp, data, const)
    return hrp + "1" + "".join(BECH32_CHARSET[d] for d in combined)


def bech32_decode(address: str) -> tuple[str, list[int], str]:
    if not address:
        raise ValueError("empty bech32 string")
    if any(ord(c) < 33 or ord(c) > 126 for c in address):
        raise ValueError("bech32 string contains invalid characters")
    if address.lower() != address and address.upper() != address:
        raise ValueError("mixed-case bech32 string")
    address = address.lower()
    pos = address.rfind("1")
    if pos < 1 or pos + 7 > len(address):
        raise ValueError("invalid bech32 separator position")
    hrp = address[:pos]
    data_part = address[pos + 1:]
    data = []
    for c in data_part:
        if c not in BECH32_INDEX:
            raise ValueError(f"invalid bech32 character: {c!r}")
        data.append(BECH32_INDEX[c])
    if len(data) < 6:
        raise ValueError("bech32 data too short")
    check = bech32_polymod(bech32_hrp_expand(hrp) + data)
    if check == BECH32_CONST:
        spec = "bech32"
    elif check == BECH32M_CONST:
        spec = "bech32m"
    else:
        raise ValueError("bech32 checksum mismatch")
    return hrp, data[:-6], spec


def convertbits(data: bytes | list[int], from_bits: int, to_bits: int, pad: bool = True) -> list[int]:
    acc = 0
    bits = 0
    result: list[int] = []
    maxv = (1 << to_bits) - 1
    max_acc = (1 << (from_bits + to_bits - 1)) - 1
    for value in data:
        if value < 0 or value >> from_bits:
            raise ValueError("invalid convertbits input")
        acc = ((acc << from_bits) | value) & max_acc
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            result.append((acc >> bits) & maxv)
    if pad:
        if bits:
            result.append((acc << (to_bits - bits)) & maxv)
    else:
        if bits >= from_bits:
            raise ValueError("invalid padding")
        if ((acc << (to_bits - bits)) & maxv) != 0:
            raise ValueError("non-zero padding")
    return result


def encode_segwit_address(hrp: str, witness_version: int, witness_program: bytes) -> str:
    if not 0 <= witness_version <= 16:
        raise ValueError("invalid witness version")
    if witness_version == 0:
        if len(witness_program) not in (20, 32):
            raise ValueError("invalid witness v0 program length")
        const = BECH32_CONST
    else:
        if witness_version == 1 and len(witness_program) != 32:
            raise ValueError("invalid witness v1 program length")
        const = BECH32M_CONST
    data = [witness_version] + convertbits(witness_program, 8, 5, pad=True)
    return bech32_encode(hrp, data, const)


def decode_segwit_address(address: str) -> tuple[str, int, bytes, str]:
    hrp, data, spec = bech32_decode(address)
    if not data:
        raise ValueError("empty segwit data")
    version = data[0]
    if version > 16:
        raise ValueError("invalid witness version")
    program = bytes(convertbits(data[1:], 5, 8, pad=False))
    if version == 0:
        if spec != "bech32":
            raise ValueError("witness v0 must use bech32")
        if len(program) not in (20, 32):
            raise ValueError("invalid witness v0 program length")
    else:
        if spec != "bech32m":
            raise ValueError("witness v1+ must use bech32m")
    return hrp, version, program, spec


# =============================================================================
# BIP39
# =============================================================================

def get_wordlist() -> list[str]:
    words = [line.strip() for line in BIP39_ENGLISH_WORDLIST_TEXT.splitlines() if line.strip()]
    validate_wordlist(words)
    return words


def validate_wordlist(words: list[str]) -> None:
    if len(words) != 2048:
        raise ValueError(f"BIP39 English wordlist must contain 2048 words; got {len(words)}")
    if len(set(words)) != 2048:
        raise ValueError("BIP39 English wordlist contains duplicates")
    if words != sorted(words):
        raise ValueError("BIP39 English wordlist is not sorted")
    if any(word != word.lower() for word in words):
        raise ValueError("BIP39 English wordlist must be lowercase")
    prefixes = [word[:4] for word in words]
    if len(set(prefixes)) != 2048:
        raise ValueError("BIP39 English wordlist first-four-letter prefixes are not unique")
    blob = ("\n".join(words) + "\n").encode("utf-8")
    digest = sha256(blob).hex()
    if digest != EXPECTED_BIP39_WORDLIST_SHA256:
        raise ValueError(f"embedded wordlist SHA256 mismatch: {digest}")


def entropy_to_mnemonic(entropy: bytes, words: list[str]) -> str:
    ent_bits = len(entropy) * 8
    if ent_bits not in (128, 160, 192, 224, 256):
        raise ValueError("entropy must be 128, 160, 192, 224, or 256 bits")
    checksum_len = ent_bits // 32
    bitstring = bytes_to_bits(entropy) + bytes_to_bits(sha256(entropy))[:checksum_len]
    indices = [int(bitstring[i:i + 11], 2) for i in range(0, len(bitstring), 11)]
    return " ".join(words[i] for i in indices)


def generate_24_word_mnemonic(words: list[str]) -> tuple[str, str]:
    entropy = secrets.token_bytes(32)
    mnemonic = entropy_to_mnemonic(entropy, words)
    validation = validate_mnemonic(mnemonic, words, require_24=True)
    if not validation.checksum_valid:
        raise RuntimeError("generated mnemonic failed checksum validation")
    return mnemonic, entropy.hex()


@dataclass(frozen=True)
class MnemonicValidation:
    mnemonic: str
    word_count: int
    entropy_bits: int
    checksum_bits_len: int
    entropy_hex: str
    checksum_bits: str
    expected_checksum_bits: str
    checksum_valid: bool


def validate_mnemonic(mnemonic: str, words: list[str], require_24: bool = True) -> MnemonicValidation:
    mnemonic = normalize_mnemonic(mnemonic)
    parts = mnemonic.split(" ") if mnemonic else []
    if require_24 and len(parts) != 24:
        raise ValueError(f"this tool requires exactly 24 BIP39 words; got {len(parts)}")
    if len(parts) not in (12, 15, 18, 21, 24):
        raise ValueError("BIP39 mnemonic must contain 12, 15, 18, 21, or 24 words")
    word_to_index = {word: i for i, word in enumerate(words)}
    unknown = [word for word in parts if word not in word_to_index]
    if unknown:
        raise ValueError(f"mnemonic contains non-BIP39 words: {unknown}")
    bitstring = "".join(f"{word_to_index[word]:011b}" for word in parts)
    ent_bits = len(bitstring) * 32 // 33
    checksum_len = ent_bits // 32
    entropy_bits = bitstring[:ent_bits]
    checksum_bits = bitstring[ent_bits:]
    entropy = bits_to_bytes(entropy_bits)
    expected = bytes_to_bits(sha256(entropy))[:checksum_len]
    return MnemonicValidation(
        mnemonic=mnemonic,
        word_count=len(parts),
        entropy_bits=ent_bits,
        checksum_bits_len=checksum_len,
        entropy_hex=entropy.hex(),
        checksum_bits=checksum_bits,
        expected_checksum_bits=expected,
        checksum_valid=(checksum_bits == expected),
    )


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    mnemonic = normalize_text(normalize_mnemonic(mnemonic))
    passphrase = normalize_text(passphrase)
    return hashlib.pbkdf2_hmac(
        "sha512",
        mnemonic.encode("utf-8"),
        ("mnemonic" + passphrase).encode("utf-8"),
        2048,
        dklen=64,
    )


# =============================================================================
# secp256k1 keys, WIF, single-key addresses
# =============================================================================

def private_key_to_point(privkey: int):
    if not 1 <= privkey < N:
        raise ValueError("private key must be in range [1, n-1]")
    return G * privkey


def private_key_to_public_key_compressed(privkey: int) -> bytes:
    point = private_key_to_point(privkey)
    return (b"\x02" if point.y() % 2 == 0 else b"\x03") + point.x().to_bytes(32, "big")


def private_key_to_public_key_uncompressed(privkey: int) -> bytes:
    point = private_key_to_point(privkey)
    return b"\x04" + point.x().to_bytes(32, "big") + point.y().to_bytes(32, "big")


def private_key_to_wif(privkey: int, network: Network = "mainnet", compressed: bool = True) -> str:
    if not 1 <= privkey < N:
        raise ValueError("invalid private key")
    prefix = b"\x80" if network == "mainnet" else b"\xef"
    payload = prefix + ser256(privkey) + (b"\x01" if compressed else b"")
    return base58check_encode(payload)


@dataclass(frozen=True)
class ImportedPrivateKey:
    privkey: int
    source_format: str
    source_network: str | None
    source_compressed: bool | None


def parse_wif(text: str) -> ImportedPrivateKey:
    payload = base58check_decode(text)
    if len(payload) not in (33, 34):
        raise ValueError("invalid WIF length")
    prefix = payload[0]
    if prefix == 0x80:
        network: str | None = "mainnet"
    elif prefix == 0xEF:
        network = "testnet"
    else:
        raise ValueError("invalid WIF network prefix")
    if len(payload) == 34:
        if payload[-1] != 0x01:
            raise ValueError("invalid compressed WIF suffix")
        compressed = True
        key_bytes = payload[1:-1]
    else:
        compressed = False
        key_bytes = payload[1:]
    privkey = int.from_bytes(key_bytes, "big")
    if not 1 <= privkey < N:
        raise ValueError("WIF private key is outside secp256k1 range")
    return ImportedPrivateKey(privkey, "WIF", network, compressed)


def parse_private_key(text: str) -> ImportedPrivateKey:
    original = text.strip()
    if not original:
        raise ValueError("empty private key")

    # WIF first, because WIF has checksum and explicit network.
    try:
        return parse_wif(original)
    except Exception:
        pass

    s = original.replace("_", "").strip()
    lower = s.lower()
    source = ""

    if lower.startswith("hex:"):
        raw = lower[4:].strip()
        source = "hex"
        privkey = int(raw, 16)
    elif lower.startswith("dec:"):
        raw = lower[4:].strip()
        source = "decimal"
        privkey = int(raw, 10)
    elif lower.startswith("0x"):
        raw = lower[2:]
        source = "0x-hex"
        privkey = int(raw, 16)
    elif all(c in "0123456789abcdefABCDEF" for c in s) and len(s) == 64:
        source = "hex-64"
        privkey = int(s, 16)
    elif any(c in "abcdefABCDEF" for c in s) and all(c in "0123456789abcdefABCDEF" for c in s):
        source = "hex"
        privkey = int(s, 16)
    elif s.isdecimal():
        source = "decimal"
        privkey = int(s, 10)
    else:
        raise ValueError("private key is not valid WIF, hex, 0x-hex, or decimal")

    if not 1 <= privkey < N:
        raise ValueError("private key must be in secp256k1 range [1, n-1]")
    return ImportedPrivateKey(privkey, source, None, None)


def tagged_hash(tag: str, msg: bytes) -> bytes:
    tag_hash = sha256(tag.encode("ascii"))
    return sha256(tag_hash + tag_hash + msg)


def taproot_output_key_from_private_key(privkey: int) -> bytes:
    internal_point = private_key_to_point(privkey)
    if internal_point.y() % 2 == 1:
        internal_point = G * (N - privkey)
    internal_x = internal_point.x().to_bytes(32, "big")
    tweak = int.from_bytes(tagged_hash("TapTweak", internal_x), "big")
    if tweak >= N:
        raise ValueError("invalid Taproot tweak")
    output_point = internal_point + (G * tweak)
    if output_point == INFINITY:
        raise ValueError("invalid Taproot output key")
    return output_point.x().to_bytes(32, "big")


# =============================================================================
# BIP32 private derivation
# =============================================================================

@dataclass(frozen=True)
class BIP32PrivateNode:
    privkey: int
    chain_code: bytes
    depth: int = 0
    parent_fingerprint: bytes = b"\x00\x00\x00\x00"
    child_number: int = 0

    @classmethod
    def from_seed(cls, seed: bytes) -> "BIP32PrivateNode":
        i = hmac_sha512(b"Bitcoin seed", seed)
        priv = int.from_bytes(i[:32], "big")
        chain = i[32:]
        if not 1 <= priv < N:
            raise ValueError("invalid master private key")
        return cls(priv, chain)

    def public_key_compressed(self) -> bytes:
        return private_key_to_public_key_compressed(self.privkey)

    def public_key_uncompressed(self) -> bytes:
        return private_key_to_public_key_uncompressed(self.privkey)

    def fingerprint(self) -> bytes:
        return hash160(self.public_key_compressed())[:4]

    def derive_child(self, index: int) -> "BIP32PrivateNode":
        if not 0 <= index <= 0xFFFFFFFF:
            raise ValueError("invalid child index")
        if index >= HARDENED:
            data = b"\x00" + ser256(self.privkey) + ser32(index)
        else:
            data = self.public_key_compressed() + ser32(index)
        i = hmac_sha512(self.chain_code, data)
        il = int.from_bytes(i[:32], "big")
        ir = i[32:]
        if il >= N:
            raise ValueError("invalid BIP32 child derivation: IL >= n")
        child_privkey = (il + self.privkey) % N
        if child_privkey == 0:
            raise ValueError("invalid BIP32 child derivation: child key is zero")
        return BIP32PrivateNode(
            privkey=child_privkey,
            chain_code=ir,
            depth=self.depth + 1,
            parent_fingerprint=self.fingerprint(),
            child_number=index,
        )

    def derive_path(self, path: str) -> "BIP32PrivateNode":
        if path in ("", "m", "M"):
            return self
        parts = path.split("/")
        if parts[0] in ("m", "M"):
            parts = parts[1:]
        node = self
        for part in parts:
            part = part.strip()
            if not part:
                continue
            hardened = part.endswith(("'", "h", "H"))
            number_text = part[:-1] if hardened else part
            if not number_text.isdigit():
                raise ValueError(f"invalid BIP32 path component: {part}")
            index = int(number_text)
            if index >= HARDENED:
                raise ValueError(f"BIP32 path index too large: {part}")
            if hardened:
                index += HARDENED
            node = node.derive_child(index)
        return node

    def serialize_xprv(self, version: bytes) -> str:
        payload = (
            version
            + bytes([self.depth])
            + self.parent_fingerprint
            + ser32(self.child_number)
            + self.chain_code
            + b"\x00"
            + ser256(self.privkey)
        )
        return base58check_encode(payload)

    def serialize_xpub(self, version: bytes) -> str:
        payload = (
            version
            + bytes([self.depth])
            + self.parent_fingerprint
            + ser32(self.child_number)
            + self.chain_code
            + self.public_key_compressed()
        )
        return base58check_encode(payload)


def coin_type_for_network(network: Network) -> int:
    return 0 if network == "mainnet" else 1


def build_account_path(purpose: int, network: Network, account: int) -> str:
    return f"m/{purpose}'/{coin_type_for_network(network)}'/{account}'"


def build_address_path(
    purpose: int,
    network: Network,
    account: int,
    change: int,
    index: int,
    harden_change: bool,
    harden_index: bool,
) -> str:
    change_suffix = "'" if harden_change else ""
    index_suffix = "'" if harden_index else ""
    return f"{build_account_path(purpose, network, account)}/{change}{change_suffix}/{index}{index_suffix}"


def extended_prefix_for_purpose(purpose: int, network: Network, private: bool) -> str:
    info = PURPOSE_INFO[purpose]
    key = f"{'xprv' if private else 'xpub'}_{network}"
    return info[key]


# =============================================================================
# Address generation and verification
# =============================================================================

@dataclass(frozen=True)
class AddressRecord:
    network: Network
    purpose: int
    purpose_label: str
    purpose_name: str
    script_type: str
    variant: str
    path: str
    index: int
    change: int
    harden_change: bool
    harden_index: bool
    address: str
    private_key_decimal: str
    private_key_hex: str
    wif_compressed: str
    wif_uncompressed: str
    public_key_compressed_hex: str
    public_key_uncompressed_hex: str
    pubkey_hash160_hex: str
    redeem_script_hex: str
    witness_version: str
    witness_program_hex: str
    script_pubkey_hex: str
    bech32_spec: str
    account_xprv_prefix: str
    account_xprv: str
    account_xpub_prefix: str
    account_xpub: str
    validation: str


def single_key_address_details(privkey: int, purpose: int, network: Network) -> dict[str, str]:
    pub_c = private_key_to_public_key_compressed(privkey)
    pub_u = private_key_to_public_key_uncompressed(privkey)
    pubkey_hash = hash160(pub_c)

    if purpose == 44:
        version = b"\x00" if network == "mainnet" else b"\x6f"
        address = base58check_encode(version + pubkey_hash)
        script_pubkey = b"\x76\xa9\x14" + pubkey_hash + b"\x88\xac"
        redeem_script = b""
        witness_version = ""
        witness_program = b""
        bech32_spec = ""
    elif purpose == 49:
        redeem_script = b"\x00\x14" + pubkey_hash
        script_hash = hash160(redeem_script)
        version = b"\x05" if network == "mainnet" else b"\xc4"
        address = base58check_encode(version + script_hash)
        script_pubkey = b"\xa9\x14" + script_hash + b"\x87"
        witness_version = "0"
        witness_program = pubkey_hash
        bech32_spec = "wrapped-v0"
    elif purpose == 84:
        hrp = "bc" if network == "mainnet" else "tb"
        address = encode_segwit_address(hrp, 0, pubkey_hash)
        script_pubkey = b"\x00\x14" + pubkey_hash
        redeem_script = b""
        witness_version = "0"
        witness_program = pubkey_hash
        bech32_spec = "bech32"
    elif purpose == 86:
        hrp = "bc" if network == "mainnet" else "tb"
        output_key = taproot_output_key_from_private_key(privkey)
        address = encode_segwit_address(hrp, 1, output_key)
        script_pubkey = b"\x51\x20" + output_key
        redeem_script = b""
        witness_version = "1"
        witness_program = output_key
        bech32_spec = "bech32m"
    else:
        raise ValueError(f"unsupported purpose: {purpose}")

    return {
        "address": address,
        "private_key_decimal": str(privkey),
        "private_key_hex": ser256(privkey).hex(),
        "wif_compressed": private_key_to_wif(privkey, network, True),
        "wif_uncompressed": private_key_to_wif(privkey, network, False),
        "public_key_compressed_hex": pub_c.hex(),
        "public_key_uncompressed_hex": pub_u.hex(),
        "pubkey_hash160_hex": pubkey_hash.hex(),
        "redeem_script_hex": redeem_script.hex(),
        "witness_version": witness_version,
        "witness_program_hex": witness_program.hex(),
        "script_pubkey_hex": script_pubkey.hex(),
        "bech32_spec": bech32_spec,
    }


def validate_address_structure(address: str, purpose: int, network: Network) -> str:
    if purpose in (44, 49):
        payload = base58check_decode(address)
        expected_prefix = {
            (44, "mainnet"): 0x00,
            (44, "testnet"): 0x6F,
            (49, "mainnet"): 0x05,
            (49, "testnet"): 0xC4,
        }[(purpose, network)]
        if payload[0] != expected_prefix:
            raise ValueError("base58 address version mismatch")
        if len(payload) != 21:
            raise ValueError("base58 address payload length mismatch")
        return "OK: Base58Check checksum/version/length verified"

    hrp, version, program, spec = decode_segwit_address(address)
    expected_hrp = "bc" if network == "mainnet" else "tb"
    if hrp != expected_hrp:
        raise ValueError("segwit HRP mismatch")
    if purpose == 84:
        if version != 0 or len(program) != 20 or spec != "bech32":
            raise ValueError("BIP84 address must be v0/bech32/20-byte program")
        return "OK: Bech32 checksum/hrp/v0/20-byte witness program verified"
    if purpose == 86:
        if version != 1 or len(program) != 32 or spec != "bech32m":
            raise ValueError("BIP86 address must be v1/bech32m/32-byte program")
        return "OK: Bech32m checksum/hrp/v1/32-byte witness program verified"
    raise ValueError("unsupported purpose")


def make_address_record(
    master: BIP32PrivateNode,
    network: Network,
    purpose: int,
    account: int,
    change: int,
    index: int,
    variant: str,
    harden_change: bool,
    harden_index: bool,
) -> AddressRecord:
    account_path = build_account_path(purpose, network, account)
    path = build_address_path(purpose, network, account, change, index, harden_change, harden_index)
    account_node = master.derive_path(account_path)
    address_node = master.derive_path(path)
    details = single_key_address_details(address_node.privkey, purpose, network)

    # Cross-check: WIF decodes back to same private key and derived address recomputes identically.
    imported = parse_private_key(details["wif_compressed"])
    if imported.privkey != address_node.privkey:
        raise RuntimeError("WIF roundtrip private key mismatch")
    recomputed = single_key_address_details(imported.privkey, purpose, network)["address"]
    if recomputed != details["address"]:
        raise RuntimeError("private-key-to-address recomputation mismatch")

    structure_validation = validate_address_structure(details["address"], purpose, network)

    # Validate expected prefix directly for human-visible safety.
    info = PURPOSE_INFO[purpose]
    expected_prefix = info[f"address_prefix_{network}"]
    if expected_prefix == "m/n":
        if not details["address"].startswith(("m", "n")):
            raise RuntimeError("testnet P2PKH prefix mismatch")
    elif not details["address"].startswith(expected_prefix):
        raise RuntimeError(f"address prefix mismatch: expected {expected_prefix}")

    xprv_prefix = extended_prefix_for_purpose(purpose, network, private=True)
    xpub_prefix = extended_prefix_for_purpose(purpose, network, private=False)
    xprv_version = EXTENDED_KEY_VERSIONS[network][xprv_prefix]
    xpub_version = EXTENDED_KEY_VERSIONS[network][xpub_prefix]
    account_xprv = account_node.serialize_xprv(xprv_version)
    account_xpub = account_node.serialize_xpub(xpub_version)

    # Validate extended key checksum and depth.
    xprv_payload = base58check_decode(account_xprv)
    xpub_payload = base58check_decode(account_xpub)
    if xprv_payload[:4] != xprv_version or xpub_payload[:4] != xpub_version:
        raise RuntimeError("extended key version mismatch")
    if xprv_payload[4] != 3 or xpub_payload[4] != 3:
        raise RuntimeError("account extended key depth must be 3")

    return AddressRecord(
        network=network,
        purpose=purpose,
        purpose_label=PURPOSE_INFO[purpose]["label"],
        purpose_name=PURPOSE_INFO[purpose]["name"],
        script_type=PURPOSE_INFO[purpose]["script_type"],
        variant=variant,
        path=path,
        index=index,
        change=change,
        harden_change=harden_change,
        harden_index=harden_index,
        address=details["address"],
        private_key_decimal=details["private_key_decimal"],
        private_key_hex=details["private_key_hex"],
        wif_compressed=details["wif_compressed"],
        wif_uncompressed=details["wif_uncompressed"],
        public_key_compressed_hex=details["public_key_compressed_hex"],
        public_key_uncompressed_hex=details["public_key_uncompressed_hex"],
        pubkey_hash160_hex=details["pubkey_hash160_hex"],
        redeem_script_hex=details["redeem_script_hex"],
        witness_version=details["witness_version"],
        witness_program_hex=details["witness_program_hex"],
        script_pubkey_hex=details["script_pubkey_hex"],
        bech32_spec=details["bech32_spec"],
        account_xprv_prefix=xprv_prefix,
        account_xprv=account_xprv,
        account_xpub_prefix=xpub_prefix,
        account_xpub=account_xpub,
        validation=structure_validation + "; private/WIF/address/xpub/xprv cross-check OK",
    )


# =============================================================================
# Printing wallet reports
# =============================================================================

def print_mnemonic_report(validation: MnemonicValidation, seed: bytes, passphrase: str, generated_entropy_hex: str | None) -> None:
    print_header("BIP39 24-WORD MNEMONIC / 助记词")
    if generated_entropy_hex is not None:
        print_kv("Generated entropy hex", generated_entropy_hex)
    print_kv("Mnemonic word count", validation.word_count)
    print_kv("Entropy bits", validation.entropy_bits)
    print_kv("Checksum bits", validation.checksum_bits_len)
    print_kv("Checksum valid", validation.checksum_valid)
    print_kv("Passphrase used", bool(passphrase))
    print_kv("Mnemonic", validation.mnemonic)
    print_kv("Entropy hex", validation.entropy_hex)
    print_kv("Seed hex", seed.hex())


def print_first_addresses(master: BIP32PrivateNode, network: Network, account: int, change: int) -> None:
    print_header("FIRST STANDARD RECEIVING ADDRESS / 首个标准收款地址，bc1 会优先显示")
    for purpose in PRINT_ORDER:
        rec = make_address_record(master, network, purpose, account, change, 0, "standard", False, False)
        print(f"{rec.purpose_label:<6} | {rec.purpose_name:<36} | path={rec.path:<22} | address={rec.address}")
    print("-" * 100)
    print("确认：BIP84 应显示 bc1q...；BIP86 应显示 bc1p...。")


def print_record_summary(rec: AddressRecord) -> None:
    print(
        f"{rec.purpose_label:<6} | {rec.variant:<27} | index={rec.index:<6} | "
        f"path={rec.path:<28} | address={rec.address}"
    )


def print_record_full(rec: AddressRecord) -> None:
    print_subheader(f"{rec.purpose_label} | {rec.purpose_name} | {rec.variant} | index={rec.index}")
    print_kv("Network", rec.network)
    print_kv("Purpose", f"{rec.purpose} / {rec.purpose_label}")
    print_kv("Script type", rec.script_type)
    print_kv("Path", rec.path)
    print_kv("Address", rec.address)
    print_kv("ScriptPubKey hex", rec.script_pubkey_hex)
    print_kv("Redeem script hex", rec.redeem_script_hex or "N/A")
    print_kv("Witness version", rec.witness_version or "N/A")
    print_kv("Witness program hex", rec.witness_program_hex or "N/A")
    print_kv("Bech32 spec", rec.bech32_spec or "N/A")
    print_kv("Public key compressed", rec.public_key_compressed_hex)
    print_kv("Public key uncompressed", rec.public_key_uncompressed_hex)
    print_kv("HASH160(pubkey)", rec.pubkey_hash160_hex)
    print_kv("Private key decimal", rec.private_key_decimal)
    print_kv("Private key hex", rec.private_key_hex)
    print_kv("WIF compressed", rec.wif_compressed)
    print_kv("WIF uncompressed", rec.wif_uncompressed)
    print_kv(f"Account {rec.account_xpub_prefix}", rec.account_xpub)
    print_kv(f"Account {rec.account_xprv_prefix}", rec.account_xprv)
    print_kv("Validation", rec.validation)


def print_hd_wallet(
    mnemonic: str,
    passphrase: str,
    count: int,
    network: Network = "mainnet",
    account: int = 0,
    change: int = 0,
    generated_entropy_hex: str | None = None,
) -> None:
    words = get_wordlist()
    validation = validate_mnemonic(mnemonic, words, require_24=True)
    if not validation.checksum_valid:
        raise ValueError("BIP39 checksum invalid; refusing to derive addresses")
    seed = mnemonic_to_seed(validation.mnemonic, passphrase)
    master = BIP32PrivateNode.from_seed(seed)

    print_mnemonic_report(validation, seed, passphrase, generated_entropy_hex)
    print_header("HD CONFIG / 自动派生配置")
    print_kv("Network", network)
    print_kv("Coin type", coin_type_for_network(network))
    print_kv("Account", account)
    print_kv("Change", f"{change} (0=receiving/external)")
    print_kv("Address indexes", f"0 .. {count - 1}")
    print_kv("Purposes", "BIP84, BIP86, BIP44, BIP49")
    print_kv("Derivation variants", ", ".join(v[0] for v in DERIVATION_VARIANTS))
    print_kv("Master fingerprint", master.fingerprint().hex())
    print_kv("Master xprv", master.serialize_xprv(EXTENDED_KEY_VERSIONS[network]["xprv" if network == "mainnet" else "tprv"]))
    print_kv("Master xpub", master.serialize_xpub(EXTENDED_KEY_VERSIONS[network]["xpub" if network == "mainnet" else "tpub"]))
    print("\n说明：standard 是钱包兼容性最高的路径；包含 hardened 的 change/index 变体是 BIP32 合法但非常规 watch-only 用法。")

    print_first_addresses(master, network, account, change)

    print_header("ADDRESS SUMMARY / 地址总览")
    for variant, harden_change, harden_index in DERIVATION_VARIANTS:
        print_subheader(f"SUMMARY VARIANT: {variant}")
        for index in range(count):
            for purpose in PRINT_ORDER:
                rec = make_address_record(master, network, purpose, account, change, index, variant, harden_change, harden_index)
                print_record_summary(rec)

    print_header("FULL ADDRESS DETAILS / 完整地址细节")
    for variant, harden_change, harden_index in DERIVATION_VARIANTS:
        for index in range(count):
            for purpose in PRINT_ORDER:
                rec = make_address_record(master, network, purpose, account, change, index, variant, harden_change, harden_index)
                print_record_full(rec)

    print_header("DONE")
    print("所有地址已完成：BIP39 checksum、BIP32 派生、私钥/WIF、公钥、地址编码、Base58Check/Bech32/Bech32m、xpub/xprv 交叉校验。")


def print_single_private_key_report(imported: ImportedPrivateKey) -> None:
    privkey = imported.privkey
    print_header("IMPORTED PRIVATE KEY / 导入私钥")
    print_kv("Detected source format", imported.source_format)
    print_kv("Source network", imported.source_network or "N/A for raw private key")
    print_kv("Source WIF compressed", imported.source_compressed if imported.source_compressed is not None else "N/A")
    print_kv("Private key decimal", str(privkey))
    print_kv("Private key hex", ser256(privkey).hex())
    print_kv("Curve range check", "OK: 1 <= key < secp256k1 n")
    print_kv("Public key compressed", private_key_to_public_key_compressed(privkey).hex())
    print_kv("Public key uncompressed", private_key_to_public_key_uncompressed(privkey).hex())

    for network in ("mainnet", "testnet"):
        print_subheader(f"PRIVATE KEY FORMATS ON {network.upper()}")
        print_kv("WIF compressed", private_key_to_wif(privkey, network, True))
        print_kv("WIF uncompressed", private_key_to_wif(privkey, network, False))

    for network in ("mainnet", "testnet"):
        print_header(f"SINGLE-KEY ADDRESSES ON {network.upper()} / 非 HD 单私钥地址")
        for purpose in PRINT_ORDER:
            info = PURPOSE_INFO[purpose]
            details = single_key_address_details(privkey, purpose, network)  # type: ignore[arg-type]
            validation = validate_address_structure(details["address"], purpose, network)  # type: ignore[arg-type]
            print_subheader(f"{info['label']} | {info['name']} | {info['script_type']}")
            print_kv("Address", details["address"])
            print_kv("ScriptPubKey hex", details["script_pubkey_hex"])
            print_kv("Redeem script hex", details["redeem_script_hex"] or "N/A")
            print_kv("Witness version", details["witness_version"] or "N/A")
            print_kv("Witness program hex", details["witness_program_hex"] or "N/A")
            print_kv("Bech32 spec", details["bech32_spec"] or "N/A")
            print_kv("Validation", validation + "; private key -> public key -> address OK")


# =============================================================================
# Self-test
# =============================================================================

def assert_equal(name: str, got: object, expected: object) -> None:
    if got != expected:
        raise AssertionError(f"{name} failed\nGOT     : {got!r}\nEXPECTED: {expected!r}")


def run_self_test(verbose: bool = True) -> None:
    def ok(msg: str) -> None:
        if verbose:
            print(f"[OK] {msg}")

    words = get_wordlist()
    ok("embedded BIP39 wordlist length/uniqueness/sort/SHA256")

    mnemonic_12 = entropy_to_mnemonic(bytes.fromhex("00000000000000000000000000000000"), words)
    assert_equal("BIP39 zero entropy mnemonic", mnemonic_12, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
    ok("BIP39 entropy -> mnemonic vector")

    val12 = validate_mnemonic(mnemonic_12, words, require_24=False)
    assert_equal("BIP39 checksum vector", val12.checksum_valid, True)
    assert_equal("BIP39 entropy vector", val12.entropy_hex, "00000000000000000000000000000000")
    ok("BIP39 mnemonic -> entropy/checksum vector")

    seed_trezor = mnemonic_to_seed(mnemonic_12, "TREZOR").hex()
    assert_equal(
        "BIP39 seed vector",
        seed_trezor,
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
        "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
    )
    ok("BIP39 PBKDF2-HMAC-SHA512 seed vector")

    mnemonic_24_zero = entropy_to_mnemonic(bytes(32), words)
    val24 = validate_mnemonic(mnemonic_24_zero, words, require_24=True)
    assert_equal("BIP39 24-word zero entropy checksum", val24.checksum_valid, True)
    assert_equal("BIP39 24-word zero entropy count", val24.word_count, 24)
    ok("BIP39 24-word generation/checksum vector")

    for _ in range(5):
        m, ent = generate_24_word_mnemonic(words)
        v = validate_mnemonic(m, words, require_24=True)
        assert_equal("random 24-word checksum", v.checksum_valid, True)
        assert_equal("random entropy length", len(ent), 64)
    ok("random 24-word mnemonic generation and checksum")

    invalid_validation = validate_mnemonic("abandon " * 23 + "zoo", words, require_24=True)
    if invalid_validation.checksum_valid:
        raise AssertionError("invalid BIP39 checksum was accepted as valid")
    try:
        validate_mnemonic("abandon " * 23 + "notaword", words, require_24=True)
    except Exception:
        pass
    else:
        raise AssertionError("invalid BIP39 word was accepted")
    ok("invalid BIP39 checksum/word rejected")

    seed = mnemonic_to_seed(mnemonic_12, "")
    master = BIP32PrivateNode.from_seed(seed)
    known = {
        44: "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
        49: "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf",
        84: "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
        86: "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
    }
    for purpose, expected_addr in known.items():
        rec = make_address_record(master, "mainnet", purpose, 0, 0, 0, "standard", False, False)
        assert_equal(f"BIP{purpose} standard address", rec.address, expected_addr)
    ok("BIP44/BIP49/BIP84/BIP86 standard mainnet address vectors")

    # Prefix and checksum matrix: mainnet/testnet, standard and hardened variants, first 3 indexes.
    for network in ("mainnet", "testnet"):
        for variant, hc, hi in DERIVATION_VARIANTS:
            for index in range(3):
                for purpose in PRINT_ORDER:
                    rec = make_address_record(master, network, purpose, 0, 0, index, variant, hc, hi)  # type: ignore[arg-type]
                    validate_address_structure(rec.address, purpose, network)  # type: ignore[arg-type]
                    if purpose == 84 and network == "mainnet":
                        assert rec.address.startswith("bc1q")
                    if purpose == 86 and network == "mainnet":
                        assert rec.address.startswith("bc1p")
    ok("address matrix: mainnet/testnet + standard/hardened variants + indexes")

    encoded = base58check_encode(b"\x00" + b"\x11" * 20)
    bad = encoded[:-1] + ("1" if encoded[-1] != "1" else "2")
    try:
        base58check_decode(bad)
    except ValueError:
        pass
    else:
        raise AssertionError("bad Base58Check checksum accepted")
    ok("Base58Check negative checksum rejection")

    good84 = known[84]
    bad84 = good84[:-1] + ("q" if good84[-1] != "q" else "p")
    try:
        decode_segwit_address(bad84)
    except ValueError:
        pass
    else:
        raise AssertionError("bad Bech32 checksum accepted")
    ok("Bech32 negative checksum rejection")

    # Private-key import forms.
    pk = 1
    forms = [
        "1",
        "dec:1",
        "0x" + ser256(pk).hex(),
        "hex:" + ser256(pk).hex(),
        ser256(pk).hex(),
        private_key_to_wif(pk, "mainnet", True),
        private_key_to_wif(pk, "mainnet", False),
        private_key_to_wif(pk, "testnet", True),
        private_key_to_wif(pk, "testnet", False),
    ]
    for form in forms:
        imported = parse_private_key(form)
        assert_equal(f"private key import {form[:8]}", imported.privkey, pk)
    ok("private key import: decimal/hex/0x/WIF compressed/uncompressed mainnet/testnet")

    for invalid in ["0", str(N), "not-a-key", "0xzz"]:
        try:
            parse_private_key(invalid)
        except Exception:
            pass
        else:
            raise AssertionError(f"invalid private key accepted: {invalid}")
    ok("invalid private key rejection")

    # Ensure what the user cares about is visibly true.
    rec84 = make_address_record(master, "mainnet", 84, 0, 0, 0, "standard", False, False)
    rec86 = make_address_record(master, "mainnet", 86, 0, 0, 0, "standard", False, False)
    assert rec84.address.startswith("bc1q")
    assert rec86.address.startswith("bc1p")
    assert "BIP84" == rec84.purpose_label
    assert "BIP86" == rec86.purpose_label
    ok("BIP84/BIP86 explicit visibility: BIP84=bc1q, BIP86=bc1p")


# =============================================================================
# Interactive CLI
# =============================================================================

def print_intro() -> None:
    print(textwrap.dedent("""
    ================================================================================================
    Offline Bitcoin Wallet CLI / 离线比特币收款地址工具
    ================================================================================================
    默认最少输入：
      - 生成模式固定生成 24 个 BIP39 单词。
      - 只问一次 BIP39 passphrase；直接回车表示不用。
      - 自动打印 BIP84 bc1q、BIP86 bc1p、BIP44 1、BIP49 3。
      - 自动包含 standard、index-hardened、change-hardened、change-and-index-hardened 四种路径。
      - 只 print，不导出文件。
    ================================================================================================
    """).strip())


def menu() -> str:
    print("\n请选择：")
    print("  1) 生成新的 24 词 BIP39 助记词，并自动打印大量 HD 收款地址")
    print("  2) 导入已有 24 词 BIP39 助记词，并自动打印大量 HD 收款地址")
    print("  3) 导入私钥/WIF，显示十进制、十六进制、WIF、BIP44/49/84/86 地址")
    print("  4) 重新运行完整自检")
    print("  5) 退出")
    return ask_line("输入选项；直接回车=1", "1")


def run_generate_flow() -> None:
    words = get_wordlist()
    passphrase = ask_passphrase_once()
    count = ask_int("每种 BIP/每种路径变体打印多少个 index；直接回车=20", 20, minimum=1)
    mnemonic, entropy_hex = generate_24_word_mnemonic(words)
    print_hd_wallet(mnemonic, passphrase, count, network="mainnet", account=0, change=0, generated_entropy_hex=entropy_hex)


def run_import_mnemonic_flow() -> None:
    print("请粘贴 24 个英文 BIP39 单词。必须是 24 个，checksum 必须正确。")
    mnemonic = ask_line("Mnemonic")
    passphrase = ask_passphrase_once()
    count = ask_int("每种 BIP/每种路径变体打印多少个 index；直接回车=20", 20, minimum=1)
    print_hd_wallet(mnemonic, passphrase, count, network="mainnet", account=0, change=0, generated_entropy_hex=None)


def run_import_private_key_flow() -> None:
    print("支持格式：WIF、64位十六进制、0x十六进制、十进制、hex:...、dec:...")
    text = ask_line("Private key / WIF")
    imported = parse_private_key(text)
    print_single_private_key_report(imported)


def configure_stdout_for_cli() -> None:
    """Best-effort stdout line buffering for normal terminals.

    Some IDEs, online runners, PyInstaller wrappers, and Windows GUI shells
    replace sys.stdout with an object that does not implement reconfigure().
    Wallet functionality must not depend on that method, so this function is
    intentionally non-fatal.
    """
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if callable(reconfigure):
        try:
            reconfigure(line_buffering=True)
        except Exception:
            pass


def interactive_main() -> None:
    configure_stdout_for_cli()
    print_intro()
    print("启动自检中；如果失败，脚本会停止，不会生成地址。")
    run_self_test(verbose=True)
    print("Self-test result: OK\n")

    while True:
        choice = menu()
        try:
            if choice == "1":
                run_generate_flow()
            elif choice == "2":
                run_import_mnemonic_flow()
            elif choice == "3":
                run_import_private_key_flow()
            elif choice == "4":
                run_self_test(verbose=True)
                print("Self-test result: OK")
            elif choice == "5" or choice.lower() in ("q", "quit", "exit"):
                print("退出。")
                return
            else:
                print("无效选项。")
        except KeyboardInterrupt:
            print("\n已取消当前操作。")
        except Exception as exc:
            print("\nERROR / 错误：", exc)
            print("当前操作已停止；未继续生成地址。")


def main() -> None:
    # Optional non-interactive tools for real use and testing.
    if len(sys.argv) >= 2 and sys.argv[1] in ("self-test", "--self-test"):
        run_self_test(verbose=True)
        print("Self-test result: OK")
        return
    if len(sys.argv) >= 2 and sys.argv[1] in ("--help", "-h", "help"):
        print(__doc__)
        print("\n用法：")
        print("  python bitcoin_hd_wallet_real_cli.py")
        print("  python bitcoin_hd_wallet_real_cli.py self-test")
        return
    interactive_main()


if __name__ == "__main__":
    main()

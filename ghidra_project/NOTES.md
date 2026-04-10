The client is probably from January 2006. It was downloaded from `https://archive.org/details/ragnaroklevelup2006`.

```
[sekai@void ragnarok2006]$ find . -type f -printf "%TY-%Tm-%Td %TH:%TM:%TS %p\\n" | sort -r | grep 2006 | grep -v 'ghidra' | head
2006-01-31 13:04:10.0000000000 ./GameGuard/npgm.erl
2006-01-31 13:04:06.0000000000 ./GameGuard/npsc.erl
2006-01-31 13:04:06.0000000000 ./GameGuard/npgl.erl
2006-01-31 13:03:46.0000000000 ./GameGuard/npgg.erl
2006-01-31 13:03:44.0000000000 ./GameGuard/npgmup.erl
2006-01-31 13:03:36.0000000000 ./GameGuard/GameGuard.ver
2006-01-31 11:30:08.0000000000 ./patch.inf
2006-01-31 11:30:08.0000000000 ./licence.txt
2006-01-31 11:30:08.0000000000 ./data.grf
2006-01-31 11:30:04.0000000000 ./BGM/83.mp3
```

Dentro de `licence.txt` existe a string `São Paulo, 10 de Janeiro de 2006`.

According to `eAthena`, it is probably `packet_ver 19`. Maybe it's `packet_ver 20`.
```
//2005-07-19bSakexe
packet_ver: 19
0x0072,34,useskilltoid,6:17:30
0x007e,113,useskilltoposinfo,12:15:18:31:33
0x0085,17,changedir,8:16
0x0089,13,ticksend,9
0x008c,8,getcharnamerequest,4
0x0094,31,movetokafra,16:27
0x009b,32,wanttoconnection,9:15:23:27:31
0x009f,19,useitem,9:15
0x00a2,9,solvecharname,5
0x00a7,11,walktoxy,8
0x00f5,13,takeitem,9
0x00f7,18,movefromkafra,11:14
0x0113,33,useskilltopos,12:15:18:31
0x0116,12,dropitem,3:10
0x0190,24,actionrequest,11:23

//2005-08-01aSakexe
0x0245,3
0x0251,4

//2005-08-08aSakexe
0x024d,12,auctionregister,2:6:10
0x024e,4

//2005-08-17aSakexe
0x0253,3
0x0254,3,feelsaveok,0

//2005-08-29aSakexe
0x0240,-1
0x0248,-1,mailsend,2:4:28:68
0x0255,5
0x0256,0
0x0257,8

//2005-09-12bSakexe
0x0256,5
0x0258,2
0x0259,3

//2005-10-10aSakexe
0x020e,32
0x025a,-1
0x025b,6,cooking,0

//2005-10-13aSakexe
0x007a,6
0x0251,32
0x025c,4,auctionbuysell,2

//2005-10-17aSakexe
0x007a,58
0x025d,6,auctionclose,2
0x025e,4

//2005-10-24aSakexe
0x025f,6
0x0260,6

//2005-11-07aSakexe
0x0251,34,auctionsearch,2:4:8:32

//2006-01-09aSakexe
0x0261,11
0x0262,11
0x0263,11
0x0264,20
0x0265,20
0x0266,30
0x0267,4
0x0268,4
0x0269,4
0x026a,4
0x026b,4
0x026c,4
0x026d,4
0x026f,2
0x0270,2
0x0271,38
0x0272,44

//2006-01-26aSakexe
0x0271,40

//2006-03-06aSakexe
0x0273,6
0x0274,8

//2006-03-13aSakexe
0x0273,30,mailreturn,2:6
```


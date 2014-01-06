CVE-2013-4348
=============

IPIP--IP in IP
---------------
+ RFC 2003
+ RFC 791

kernel
--------




workflow
---------
1. process outter IP
    - cut off outter IP header
    - offset by iph->ihl (length of outter IP header)
2. process inner header
    - IP again, so `go to` 1.
3. if (iph->ihl == 0), 2->1 would be a dead loop.

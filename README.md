OTP code generator
===

Authy etc are annoying GUI apps that require smartphones or Chrome
extensions. This is stupid, since you can do the same thing in ~100
lines of C.

How
--

0. Run `make`
1. Store base32-encoded token in tokens dir:

```
echo -n KM4TGS2RK5CTSQKTGBDECRCGHFATAU2G > tokens/footoken
```
2. Run `otp footoken`
3. Cut and paste, or pipe output to `xclip`.

FAQ
--
1. Shouldn't you encrypt the tokens? Yes. But this program doesn't. Sorry.
2. What about QR codes? You'll need to solve that with other software. Sorry.
3. Where do my tokens go? See Makefile.

pam_miniotp
===========

[mini]-OTP module for PAM writen in Python (to use with pam_python.so).

WARNING
=======

This code is not meant to be secure. It's for educational purpose only. Use it at your own risks.

How to use
===========

Copy the file pam_miniotp.py in /lib/security
Once it's done, add this line at the end of the file /etc/pam.d/login:

auth required pam_python.so /lib/security/pam_miniotp.py

Configuration
===========

For each user, create a file in /home/<username>/.pam_miniotp
And put the SECRET inside, without a '\n'.

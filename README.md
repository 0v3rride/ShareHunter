# ShareHunter.py
This is a work in progress and does not fully function as intended.

Finds smb/samba shares on the network as quickly or as slowly as you want.
* Requires Python 3 and pysmb. 
* At the moment, it works more efficiently with on Windows
* I'm trying to modify it so it works with the same efficiency on Linux as it does on Windows

### Why?
* MSF auxiliary/scanner/smb/smb_enumshares doesn't spider shares despite arguments given
* SMBmap's password flag doesn't allow passwords with metachars (!, ?, etc.) due to the way bash interprets these characters
* Wanted to try something new.

Password as Private Key
=======================

PPK Version 1.x Copyright (c) 2009 Mehdi Sotoodeh. All rights reserved. 

PPK (Password as Private Key) is a lightweight file encryption tool.
It utilizes K-163 ECC public key for key exchange and 128-bit AES as
the data encryption algorithm.
PPK derives the private key from your password and then uses it to
calculates the associated public key. 
The public key is presented in base-32 as a short string:

    {TK90W3ML8HPZFE9ASK1SFYL9EBUSC2WG06KW/john}
    {HBLYZLE4ZMK8KHSLPFKR5C9FL75S5G12Z6HR/mike}

Using PPK, you can use someone's public key to encrypt a file. The
person who knows the associated passord is able to decrypt this file.
See PPKGuide.pdf for more info.


IMPORTANT: You MUST read and accept attached license agreement before using PPK.

THE SOFTWARE PROVIDED HERE IS FREEWARE AND IS PLACED IN THE PUBLIC DOMAIN 
BY THE AUTHOR WITH THE HOPE THAT IT CAN BE USEFUL.
YOU SHOULD AGREE WITH THE FOLLOWING TERMS AND CONDITIONS BEFORE USING
ANY PART OF THIS PACKAGE.
THIS SOFTWARE AND THE ACCOMPANYING FILES ARE PROVIDED "AS IS" AND WITHOUT 
WARRANTIES AS TO PERFORMANCE OF MERCHANTABILITY OR ANY OTHER WARRANTIES 
WHETHER EXPRESSED OR IMPLIED.  NO WARRANTY OF FITNESS FOR A PARTICULAR 
PURPOSE IS OFFERED.  ADDITIONALLY, THE AUTHOR SHALL NOT BE HELD LIABLE 
FOR ANY LOSS OF DATA, LOSS OF REVENUE, DOWN TIME OR ANY DIRECT OR 
INDIRECT DAMAGE CAUSED BY THIS SOFTWARE. THE USER MUST ASSUME THE ENTIRE 
RISK OF USING THIS SOFTWARE.  


FILES IN THIS RELEASE
---------------------

    PPK.exe         The main application program.
    PPKGuide.pdf    User's guide.
    PPK.reg         Registry file to associate .ppk files with PPK.
    license.txt     License agreement file.
    readme.txt      This readme file.

COMMAND LINE
------------

PPK supports following command line choices:

    PPK -e filename         Encrypt filename
    PPK -d filename         Decrypt an encrypted file
    PPK filename            Calls encrypt or decrypt based on .ppk extension
                            or internal file information.
    PPK                     Starts PPK GUI and interactive mode.

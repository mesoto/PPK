Password as Private Key
=======================

PPK Version 1.x Copyright (c) 2009 Mehdi Sotoodeh. All rights reserved. 

See docs/PPKGuide.pdf

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

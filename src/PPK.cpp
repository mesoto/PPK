/**
 * PPK.cpp
 *
 * Written by: Mehdi Sotoodeh
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#include "stdafx.h"
#include "PPK.h"
#include "PPKFile.h"
#include "KeyPair.h"

// Global Variables:
HINSTANCE hInst;								// current instance
HICON hIcon;

unsigned char Password[MAX_PW_LENGTH+1];
PPKFile K;
CKeyFile KeyFile;
CKeyPair UserKey;       // key pair generated from user input

OPENFILENAME ofn;

// a another memory buffer to contain the file name
unsigned char Buffer[0x8000];
unsigned long PPK_Flags = 0;

// Values for PPK_Flags:

#define F_DELETE_SRC_E      0x0001
#define F_OVWRITE_DST_E     0x0002
#define F_DELETE_SRC_D      0x0010
#define F_OVWRITE_DST_D     0x0020
#define F_DOUBLE_KEY        0x0100
#define F_WEAK_PSW          0x0200
 
// Forward declarations of functions included in this code module:
INT_PTR CALLBACK MainDlgProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK AboutDlgProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK EncryptFileDlgProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK DecryptFileDlgProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK ManageKeysDlgProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK GenKeyDlgProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK GetPasswordDlgProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK DisplayKeyDlgProc(HWND, UINT, WPARAM, LPARAM);

extern "C" int ProcessCommandLine( LPTSTR lpCmdLine );
extern "C" unsigned long GetMSBF32( unsigned char * buff );

int GetNextToken( LPSTR buff, int max_size, LPSTR * pCmdLine )
{
    int i;
    LPSTR p = *pCmdLine;

    while( *p == ' ' || *p == '\t' ) p++;
    if( *p == '"' )
    {
        p++;
        for( i = 0; i < max_size && *p != '\0'; buff[i++] = *p++ )
        {
            if( *p == '"' ) { p++; break; }
        }
    }
    else
    {
        for( i = 0; i < max_size && *p != '\0'; buff[i++] = *p++ )
        {
            if( *p == ' ' || *p == '\t') break;
        }
    }
    *pCmdLine = p;
    buff[i] = '\0';
    return i;
}

int APIENTRY _tWinMain(
    HINSTANCE hInstance,
    HINSTANCE hPrevInstance,
    LPTSTR    lpCmdLine,
    int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);

    hInst = hInstance; // Store instance handle in our global variable
	hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_PPK));
    if( GetEnvironmentVariable( "PPKCONFIG", (LPSTR)&Buffer[0], 20 ))
    {
        sscanf_s( (const char *)&Buffer[0], "%x", &PPK_Flags ); 
    }

    if( lpCmdLine != NULL )
    {
        // MessageBox( NULL, lpCmdLine, "lpCmdLine", MB_OKCANCEL );

        int n = GetNextToken( (LPSTR)&Buffer[0], 260, &lpCmdLine );

        if( n > 0 ) switch( Buffer[0] )
        {
        case '-':
        case '/':
            switch( Buffer[1] )
            {
            case 'e':
                if( GetNextToken( (LPSTR)&Buffer[0], 260, &lpCmdLine ) > 0 ) goto encrypt_file;
                break;

            case 'd':
                if( GetNextToken( (LPSTR)&Buffer[0], 260, &lpCmdLine ) > 0 )  goto decrypt_file;
                break;
            }
            break;

        case '\0':
            break;

        default:
            if( n > 4 && _stricmp( (const char *)&Buffer[n-4], ".ppk" ) == 0 )
            {
                decrypt_file:
		        return (int)DialogBoxParam(hInst, MAKEINTRESOURCE(IDD_FILE_DECRYPT), NULL, DecryptFileDlgProc, (LPARAM)&Buffer[0]);
            }

            // Check file header for magic number

            if( K.file1.Open( (char *)&Buffer[0], "rb" ) == 0 )
            {
                unsigned char buff[4];
                K.file1.ReadBytes( &buff[0], sizeof(buff) );
                K.file1.Close();

                if( GetMSBF32( &buff[0] ) == PPK_MAGIC ) goto decrypt_file;
            }
            encrypt_file:
    	    return (int)DialogBoxParam(hInst, MAKEINTRESOURCE(IDD_FILE_ENCRYPT), NULL, EncryptFileDlgProc, (LPARAM)&Buffer[0]);
        }
    }
    return (int)DialogBox( hInstance, MAKEINTRESOURCE(IDD_MAIN), NULL, MainDlgProc );
}

// Message handler to get password.
INT_PTR CALLBACK MainDlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
	case WM_INITDIALOG:
        {
            HMENU hMenu = GetSystemMenu( hDlg, FALSE );
            AppendMenu( hMenu, MF_SEPARATOR, 0, NULL );
            AppendMenu( hMenu, MF_STRING, IDM_ABOUTBOX, "About PPK..." );
        }
        // Set the icon for this dialog.  The framework does this automatically
        // when the application's main window is not a dialog
        SendMessage(hDlg, WM_SETICON, (WPARAM)FALSE, (LPARAM)hIcon);   // small icon
        SendMessage(hDlg, WM_SETICON, (WPARAM)TRUE, (LPARAM)hIcon);
        K.hWnd = hDlg;
		return (INT_PTR)TRUE;

    case WM_SYSCOMMAND:
        if( (LOWORD(wParam) & 0xFFF0) == IDM_ABOUTBOX)
        {
			DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hDlg, AboutDlgProc);
		    return (INT_PTR)TRUE;
        }
        break;

   case WM_DROPFILES:
        {
            size_t n;
            DragQueryFile((HDROP) wParam, 0, (LPSTR)&Buffer[0], sizeof(Buffer));
            DragFinish((HDROP) wParam);
            n = strlen( (const char *)&Buffer[0] );
            if( n > 4 && _stricmp( (const char *)&Buffer[n-4], ".ppk" ) == 0 )
			    DialogBoxParam(hInst, MAKEINTRESOURCE(IDD_FILE_DECRYPT), hDlg, DecryptFileDlgProc, (LPARAM)&Buffer[0]);
            else
			    DialogBoxParam(hInst, MAKEINTRESOURCE(IDD_FILE_ENCRYPT), hDlg, EncryptFileDlgProc, (LPARAM)&Buffer[0]);
        }
        break;

   case WM_COMMAND:
		switch (LOWORD(wParam))
		{
        case IDC_MANAGE_KEYS:
			DialogBox(hInst, MAKEINTRESOURCE(IDD_MANAGE_KEYS), hDlg, ManageKeysDlgProc);
			return (INT_PTR)TRUE;

		case IDC_ENCRYPT:
			DialogBox(hInst, MAKEINTRESOURCE(IDD_FILE_ENCRYPT), hDlg, EncryptFileDlgProc);
			return (INT_PTR)TRUE;

		case IDC_DECRYPT:
			DialogBox(hInst, MAKEINTRESOURCE(IDD_FILE_DECRYPT), hDlg, DecryptFileDlgProc);
			return (INT_PTR)TRUE;

        case IDCANCEL:
			EndDialog(hDlg, 0);
			return (INT_PTR)TRUE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}


// Message handler for about box.
INT_PTR CALLBACK AboutDlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:
        SendMessage(hDlg, WM_SETICON, (WPARAM)FALSE, (LPARAM)hIcon);
        return (INT_PTR)TRUE;

	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
		{
			EndDialog(hDlg, TRUE);
			return (INT_PTR)TRUE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}

extern "C" unsigned char * GetPrivateKey( HWND hWnd, unsigned char * ExpPublicKey )
{
    if( UserKey.paired == FALSE || 
        strcmp( (const char *)&UserKey.public_key_str[0], (const char *)ExpPublicKey ) != 0 )
    {
        while( 1 )
        {
            // Prompt user to enter password
            if( !DialogBoxParam( hInst, MAKEINTRESOURCE(IDD_GET_PASSWORD), hWnd, GetPasswordDlgProc, (LPARAM)ExpPublicKey ))
                return NULL;

            UserKey.GenerateKeyPair( Password );
            if( strcmp( (const char *)&UserKey.public_key_str[0], (const char *)ExpPublicKey ) == 0 ) break;

            if( MessageBox( hWnd, "Your password is not correct.\n"
                "It does not pair with used public key.", 
                "Get Password", MB_OKCANCEL | MB_ICONSTOP ) == IDCANCEL )
                return NULL;
        }
    }

    return UserKey.private_key;
}

// Message handler to get password.
INT_PTR CALLBACK GetPasswordDlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
	case WM_INITDIALOG:
        SendMessage(hDlg, WM_SETICON, (WPARAM)FALSE, (LPARAM)hIcon);
        if( lParam != NULL ) 
        {
            int rc;
            CKeyPair k;
            SetDlgItemText( hDlg, IDC_EXP_PUBKEY, (LPCSTR)lParam);

            rc = KeyFile.GetFirstKey( &k );
            while( rc == PPK_SUCCESS )
            {
                if( strcmp( (const char *)lParam, (const char *)&k.public_key_str ) == 0 )
                    break;
                rc = KeyFile.GetNextKey( &k );
            }
            KeyFile.Close();
            SetDlgItemText( hDlg, IDC_EXP_KEYID, 
                (rc == PPK_SUCCESS) ? (LPCSTR)&k.key_id[0] : "Key not on file" );
        }
        // Set keyboard focus
        PostMessage(hDlg, WM_NEXTDLGCTL, (WPARAM)GetDlgItem(hDlg, IDC_PASSWORD), TRUE);
		return (INT_PTR)TRUE;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
        case IDOK:
            GetDlgItemText( hDlg, IDC_PASSWORD, (LPSTR)&Password[0], MAX_PW_LENGTH );
			EndDialog(hDlg, TRUE);
			return (INT_PTR)TRUE;

        case IDCANCEL:
			EndDialog(hDlg, FALSE);
			return (INT_PTR)FALSE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}

/*
static BOOL updating_ui = FALSE;

static void on_edit_changed_genkey(HWND hDlg, WORD id)
{
    if (updating_ui) return;

     switch (id)
    {
        case IDC_KEY_ID:
        {
            break;
        }

    }
}
*/

INT_PTR CALLBACK GenKeyDlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    unsigned char psw2[MAX_PW_LENGTH+4];

	switch (message)
	{
	case WM_INITDIALOG:
        // Set keyboard focus
        PostMessage(hDlg, WM_NEXTDLGCTL, (WPARAM)GetDlgItem(hDlg, IDC_PASSWORD), TRUE);
        SendMessage(hDlg, WM_SETICON, (WPARAM)FALSE, (LPARAM)hIcon);
        if( PPK_Flags & F_WEAK_PSW ) CheckDlgButton(hDlg, IDC_ALLOW_WEAK, TRUE );

		return (INT_PTR)TRUE;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
            /*
        case IDC_PASSWORD2:
            if( HIWORD(wParam) == EN_CHANGE )
            {
            }
            break;

        case IDC_ALLOW_WEAK:
            if( HIWORD(wParam) == BN_CLICKED )
            {
            }
            break;
            */

        case IDOK:
            GetDlgItemText( hDlg, IDC_PASSWORD, (LPSTR)&Password[0], MAX_PW_LENGTH );
            GetDlgItemText( hDlg, IDC_PASSWORD2, (LPSTR)&psw2[0], MAX_PW_LENGTH );
            if( strcmp( (const char *)&Password[0], (const char *)&psw2[0] ) != 0 )
            {
                MessageBox( hDlg, "Two passwords do not match.", "Generate Key", MB_OK | MB_ICONSTOP );
			    return (INT_PTR)TRUE;
            }

            if( !IsDlgButtonChecked( hDlg, IDC_ALLOW_WEAK )) 
            {
                switch( CheckPasswordStrength( (unsigned char *)&Password[0] ))
                {
                case PPK_PASSWORD_TOO_SHORT:
                    MessageBox( hDlg, "Password is too short.\n"
                        "It should be at least 10 characters long.", 
                        "Generate Key", MB_OK | MB_ICONSTOP );
			        return (INT_PTR)TRUE;

                case PPK_PASSWORD_WEAK:
                    MessageBox( hDlg, "Your password is weak.\n"
                        "It should contain a mix of:\n"
                        " - Upper-case characters (A to Z).\n"
                        " - Lower-case characters (a to z).\n"
                        " - Numeric characters (0 to 9).\n"
                        " - Symbols (such as + - , * ...).",
                        "Generate Key", MB_OK | MB_ICONERROR );
			        return (INT_PTR)TRUE;

                case PPK_SUCCESS:
                    break;
                }
            }

            GetDlgItemText( hDlg, IDC_KEY_ID, (LPSTR)&UserKey.key_id[0], MAX_ID_LENGTH );
            UserKey.GenerateKeyPair( (unsigned char *)&Password[0] );

            // Clear sensitive data
            ZeroMemory( &Password[0], sizeof(Password) );
            ZeroMemory( &psw2[0], sizeof(psw2) );

			EndDialog(hDlg, TRUE);
			return (INT_PTR)TRUE;

        case IDCANCEL:
			EndDialog(hDlg, FALSE);
			return (INT_PTR)FALSE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}

#define LIST_BOX_KEY_FMT    " %c\t%s\t%s"

INT_PTR CALLBACK ManageKeysDlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    static int changed = 0;
    unsigned char buff[80];
    static int nTabs[] = { 10, 175 };

	switch (message)
	{
	case WM_INITDIALOG:
        SendMessage(hDlg, WM_SETICON, (WPARAM)FALSE, (LPARAM)hIcon);
        SendDlgItemMessage(hDlg, IDC_KEY_LIST, LB_SETTABSTOPS, (WPARAM)2, (LPARAM) nTabs);

        if( KeyFile.ReOpen( "rt" ) == PPK_SUCCESS )
        {
            while( KeyFile.GetNextKey( &UserKey ) == PPK_SUCCESS )
            {
                sprintf_s( (char *)&buff[0], sizeof(buff), LIST_BOX_KEY_FMT, 
                    UserKey.type, &UserKey.public_key_str[0], &UserKey.key_id[0] );
                SendDlgItemMessage( hDlg, IDC_KEY_LIST, LB_ADDSTRING,0,(LPARAM)&buff[0]);
            }
            KeyFile.Close();
        }
        // Set keyboard focus
        PostMessage(hDlg, WM_NEXTDLGCTL, (WPARAM)GetDlgItem(hDlg, IDC_PUB_KEY), TRUE);
        changed = 0;
		return (INT_PTR)TRUE;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
        case IDCANCEL:
			EndDialog(hDlg, FALSE);
			return (INT_PTR)FALSE;
        case IDOK:
            if( changed )
            {
                KeyFile.ReOpen( "wt" );
                for( WPARAM index = 0;; index++ )
                {
                    if( SendDlgItemMessage( hDlg, IDC_KEY_LIST, (UINT)LB_GETTEXT, 
                        index,(LPARAM)&buff[0] ) < 36 ) break;
                    if( UserKey.ExtractPublicKey(&buff[0]) == PPK_SUCCESS )
                        KeyFile.AddNewKey( &UserKey );
                }
                KeyFile.Close();
            }
			EndDialog(hDlg, TRUE);
			return (INT_PTR)TRUE;

        case IDC_REMOVE:
            SendDlgItemMessage( hDlg, IDC_KEY_LIST, LB_DELETESTRING,
                (WPARAM)SendDlgItemMessage( hDlg, IDC_KEY_LIST, LB_GETCURSEL,0,(LPARAM)0),
                (LPARAM)0);
            changed = 1;
			return (INT_PTR)TRUE;

        case IDC_IMPORT:
            GetDlgItemText( hDlg, IDC_PUB_KEY, (LPSTR)&buff[0], sizeof(buff) );
            if( UserKey.ExtractPublicKey(&buff[0]) != PPK_SUCCESS )
            {
                if( MessageBox( hDlg, "Public key is not invalid.", "Import Key", MB_OKCANCEL | MB_ICONSTOP ) == IDCANCEL )
                {
		            EndDialog(hDlg, FALSE);
		            return (INT_PTR)FALSE;
                }
	            return (INT_PTR)TRUE;
            }
            sprintf_s( (char *)&buff[0], sizeof(buff), LIST_BOX_KEY_FMT, 
                UserKey.type, &UserKey.public_key_str[0], &UserKey.key_id[0] );
            SendDlgItemMessage( hDlg, IDC_KEY_LIST, LB_ADDSTRING,0,(LPARAM)&buff[0]);
            changed = 1;
			return (INT_PTR)TRUE;

		case IDC_GEN_KEY:
	        if( DialogBox(hInst, MAKEINTRESOURCE(IDD_GENERATE_KEY), hDlg, GenKeyDlgProc))
            {
                if( DialogBox(hInst, MAKEINTRESOURCE(IDD_SHOW_KEY_INFO), hDlg, DisplayKeyDlgProc ))
                {
                    sprintf_s( (char *)&buff[0], sizeof(buff), LIST_BOX_KEY_FMT, 
                        UserKey.type, &UserKey.public_key_str[0], &UserKey.key_id[0] );
                    SendDlgItemMessage( hDlg, IDC_KEY_LIST, LB_ADDSTRING,0,(LPARAM)&buff[0]);
                    changed = 1;
                }
            }
			break;

		}
		break;
	}
	return (INT_PTR)FALSE;
}

extern "C" void StatusOut( HWND hDlg, LPSTR msg )
{
    //rc = SendMessage( hDlg, (UINT)LB_GETCURSEL,(WPARAM)0,(LPARAM)0);
    //SendMessage( hDlg, (UINT)LB_GETTEXT, (WPARAM)rc,(LPARAM)&Buffer[0] );
    //SetDlgItemText( hDlg, IDC_STATUS, msg );
    if( msg == NULL )
        SendDlgItemMessage( hDlg, IDC_STATUS, LB_RESETCONTENT,0,(LPARAM)"");
    else
    {
        LRESULT rc = SendDlgItemMessage( hDlg, IDC_STATUS, LB_ADDSTRING,0,(LPARAM)msg);
        if( rc >= 4 )   // if more than 4 lines, delete the top line
            SendDlgItemMessage( hDlg, IDC_STATUS, LB_DELETESTRING,0,(LPARAM)NULL);
    }
}

extern "C" void SetInputOutputEnc( HWND hDlg, LPSTR filename )
{
    LPSTR fname;

    GetFullPathName( (LPCSTR)filename, sizeof(Buffer), (LPSTR)&Buffer[0], &fname );
    SetDlgItemText( hDlg, IDC_FILE_NAME, (LPSTR)&Buffer[0] );
    strcat_s( (char *)&Buffer[0], sizeof(Buffer), ".ppk" );
    SetDlgItemText( hDlg, IDC_OUTPUT, (LPSTR)&Buffer[0] );
}

INT_PTR CALLBACK EncryptFileDlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    PPK_COMP_CODE cc;

	switch (message)
	{
	case WM_INITDIALOG:
        if( lParam != 0 ) SetInputOutputEnc( hDlg, (LPSTR)lParam );

        if( KeyFile.ReOpen( "rt" ) == PPK_SUCCESS )
        {
            while( KeyFile.GetNextKey( &UserKey ) == PPK_SUCCESS )
            {
                unsigned char buff[80];
                sprintf_s( (char *)&buff[0], sizeof(buff), PUB_KEY_FMT, &UserKey.public_key_str[0], &UserKey.key_id[0] );
                SendDlgItemMessage( hDlg, IDC_PUB_KEY_COMBO, CB_ADDSTRING,0,(LPARAM)&buff[0]);
            }
            KeyFile.Close();
        }

        if( PPK_Flags & F_DELETE_SRC_E  ) CheckDlgButton(hDlg, IDC_DELETE_INPUT, TRUE );
        if( PPK_Flags & F_OVWRITE_DST_E ) CheckDlgButton(hDlg, IDC_OVERWRITE, TRUE );

        SendMessage(hDlg, WM_SETICON, (WPARAM)FALSE, (LPARAM)hIcon);
        SendDlgItemMessage(hDlg, IDC_PUB_KEY_COMBO, CB_SETCURSEL, 0, 0);

        K.hWnd = hDlg;
        K.hProgress = GetDlgItem(hDlg, IDC_PROGRESS_BAR);
        SendMessage(K.hProgress, PBM_SETRANGE, 0, MAKELPARAM(0, 100)); 

        // Set keyboard focus
        PostMessage(hDlg, WM_NEXTDLGCTL, (WPARAM)GetDlgItem(hDlg, IDC_FILE_NAME), TRUE);
        //EnableWindow( GetDlgItem(hDlg, IDC_PROGRESS_BAR), FALSE);
        //EnableWindow( GetDlgItem(hDlg, IDC_STATUS), FALSE);

		return (INT_PTR)TRUE;

    case WM_DROPFILES:
        DragQueryFile((HDROP)wParam, 0, (LPSTR)&K.file1.full_path[0], sizeof(K.file1.full_path));
        DragFinish((HDROP)wParam);
        SetInputOutputEnc( hDlg, (LPSTR)&K.file1.full_path[0] );
        break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
        case IDC_BROWSE_INPUT:
            // open a file name
	        ZeroMemory( &ofn, sizeof(ofn));
	        ofn.lStructSize = sizeof(ofn);
	        ofn.hwndOwner = hDlg;
            ofn.lpstrFile = (LPSTR)&K.file1.full_path;
	        ofn.lpstrFile[0] = '\0';
            ofn.nMaxFile = sizeof(K.file1.full_path);
	        ofn.lpstrFilter = "All\0*.*\0";
	        ofn.lpstrTitle = "Select a file to encrypt";
	        ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_EXPLORER;
         
	        if( GetOpenFileName( &ofn ))
            {
                SetInputOutputEnc( hDlg, (LPSTR)&K.file1.full_path[0] );
            }
            break;

        case IDC_BROWSE_OUTPUT:
            // Select destination
	        ZeroMemory( &ofn, sizeof(ofn));
	        ofn.lStructSize = sizeof(ofn);
	        ofn.hwndOwner = hDlg;
	        ofn.lpstrFile = (LPSTR)&Buffer[0];
	        ofn.lpstrFile[0] = '\0';
	        ofn.nMaxFile = sizeof( Buffer );
	        ofn.lpstrFilter = "PPK files\0*.ppk\0";
	        ofn.lpstrTitle = "Select destination";
	        ofn.Flags = OFN_PATHMUSTEXIST | OFN_NOREADONLYRETURN | OFN_HIDEREADONLY; // | OFN_OVERWRITEPROMPT;
            ofn.lpstrDefExt = ".ppk";
         
	        if( GetSaveFileName( &ofn ))
            {
                SetDlgItemText( hDlg, IDC_OUTPUT, (LPSTR)&Buffer[0] );
            }
            break;

        case IDOK:
            GetDlgItemText( hDlg, IDC_PUB_KEY_COMBO, (LPSTR)&Buffer[0], sizeof(Buffer) );
            if( UserKey.ExtractPublicKey( Buffer ))
            {
                StatusOut( hDlg, "Public key is not valid." );
                break;
            }

            GetDlgItemText( hDlg, IDC_FILE_NAME, (LPSTR)&Buffer[0], sizeof(Buffer) );
            if( K.file1.Open( (char *)&Buffer[0], "rb" ))
                cc = PPK_FILE1_ERROR;
            else
            {
                LPSTR fname;

                GetDlgItemText( hDlg, IDC_OUTPUT, (LPSTR)&Buffer[0], sizeof(Buffer) );
                if( Buffer[0] == '\0' )
                {
                    // Nothing defined, use source path + source name + .ppk

                    strcpy_s( (char *)&Buffer[0], sizeof(Buffer), (const char *)&K.file1.full_path[0] );
                    strcat_s( (char *)&Buffer[0], sizeof(Buffer), ".ppk" );
                    SetDlgItemText( hDlg, IDC_OUTPUT, (LPSTR)&Buffer[0] );
                }
                else
                {
                    // output defined. is it file or folder?
                    HANDLE hFind;
                    WIN32_FIND_DATA FindFileData;
                    hFind = FindFirstFile( (LPCSTR)&Buffer[0], &FindFileData );
                    if( hFind != INVALID_HANDLE_VALUE )
                    {
                        if( (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 )
                        {
                            strcpy_s( (char *)&K.file2.full_path[0], sizeof(K.file2.full_path[0]), (char *)&Buffer[0] );
                            GetFullPathName( (LPCSTR)&K.file2.full_path[0], sizeof(Buffer), (LPSTR)&Buffer[0], &fname );
                            strcpy_s( (char *)&fname[0], _MAX_FNAME, (const char *)&K.file1.file_name[0] );
                            strcat_s( (char *)&fname[0], _MAX_FNAME, ".ppk" );
                            SetDlgItemText( hDlg, IDC_OUTPUT, (LPSTR)&Buffer[0] );
                        }
                        FindClose( hFind );
                    }
                }
                if( !IsDlgButtonChecked( hDlg, IDC_OVERWRITE ) && 
                    K.file2.Open( (char *)&Buffer[0], "rb" ) == PPK_SUCCESS )
                {
                    sprintf_s( (char *)&Buffer[0], sizeof(Buffer), "%s already exits.", &K.file2.file_name[0] );
                    StatusOut( hDlg, (LPSTR)&Buffer[0] );
                    K.file1.Close();
                    K.file2.Close();
                    break;
                }

                if( K.file2.Open( (char *)&Buffer[0], "wb" ))
                    cc = PPK_FILE2_ERROR;
                else
                    cc = K.EncryptFile( &UserKey.public_key[0], PPK_Flags );
            }
            K.file1.Close();
            K.file2.Close();

            switch( cc )
            {
            case PPK_SUCCESS_RETURN:
                sprintf_s( (char *)&Buffer[0], sizeof(Buffer), "%s created successfully.", &K.file2.file_name[0] );
                StatusOut( hDlg, (LPSTR)&Buffer[0] );

                if( IsDlgButtonChecked( hDlg, IDC_DELETE_INPUT ))
                {
                    DeleteFile( (LPCSTR)&K.file1.full_path[0] );
                    sprintf_s( (char *)&Buffer[0], sizeof(Buffer), "%s deleted.", &K.file1.file_name[0] );
                    StatusOut( hDlg, (LPSTR)&Buffer[0] );
                }
            case PPK_PASSWORD_NOT_VALID:
            case PPK_OPERATION_CANCELED:
			    break;

            case PPK_FILE1_ERROR:
                StatusOut( hDlg, (LPSTR)&K.file1.error_msg[0] );
			    break;

            case PPK_FILE2_ERROR:
                StatusOut( hDlg, (LPSTR)&K.file2.error_msg[0] );
			    break;
            }
	        return (INT_PTR)TRUE;

        case IDCANCEL:
	        EndDialog(hDlg, (INT_PTR)PPK_OPERATION_CANCELED);
			return (INT_PTR)FALSE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}

// This is a callback used by DecryptFileA() to set the
extern "C" int SetOutputFilename( unsigned char * defualt_name, unsigned char * filename )
{
    unsigned char buff[_MAX_PATH+_MAX_FNAME];
    LPSTR fname;
    HWND hDlg = K.hWnd;

    GetFullPathName( (LPCSTR)defualt_name, sizeof(buff), (LPSTR)&buff[0], &fname );
    if( filename != NULL ) 
        strcpy_s( fname, _MAX_FNAME, (const char *)filename );

    SetDlgItemText( hDlg, IDC_OUTPUT, (LPSTR)&buff[0] );

    if( !IsDlgButtonChecked( hDlg, IDC_OVERWRITE ))
    {
        if( K.file2.Open( (char *)&buff[0], "rb" ) == PPK_SUCCESS )
        {
            K.file2.Close();
            return K.file2.SetError( PPK_FILE_ALREDY_EXIST );
        }
    }

    return K.file2.Open( (char *)&buff[0], "wb" );
}

INT_PTR CALLBACK DecryptFileDlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    PPK_COMP_CODE cc;

	switch (message)
	{
	case WM_INITDIALOG:
        if( lParam != 0 ) SetDlgItemText( hDlg, IDC_FILE_NAME, (LPSTR)lParam );

        SendMessage(hDlg, WM_SETICON, (WPARAM)FALSE, (LPARAM)hIcon);
        if( PPK_Flags & F_DELETE_SRC_D  ) CheckDlgButton(hDlg, IDC_DELETE_INPUT, TRUE );
        if( PPK_Flags & F_OVWRITE_DST_D ) CheckDlgButton(hDlg, IDC_OVERWRITE, TRUE );

        K.hWnd = hDlg;
        K.hProgress = GetDlgItem(hDlg, IDC_PROGRESS_BAR);
        SendMessage(K.hProgress, PBM_SETRANGE, 0, MAKELPARAM(0, 100)); 
        // Set keyboard focus
        PostMessage(hDlg, WM_NEXTDLGCTL, (WPARAM)GetDlgItem(hDlg, IDC_FILE_NAME), TRUE);
		return (INT_PTR)TRUE;

    case WM_DROPFILES:
        DragQueryFile((HDROP)wParam, 0, (LPSTR)&K.file1.full_path[0], sizeof(K.file1.full_path));
        DragFinish((HDROP)wParam);
        goto set_input_output;

    case WM_COMMAND:
		switch (LOWORD(wParam))
		{
        case IDC_BROWSE_INPUT:
            // open a file to decrypt

	        ZeroMemory( &ofn, sizeof(ofn));
	        ofn.lStructSize = sizeof(ofn);
	        ofn.hwndOwner = hDlg;
            ofn.lpstrFile = (LPSTR)&K.file1.full_path[0];
	        ofn.lpstrFile[0] = '\0';
	        ofn.nMaxFile = sizeof(K.file1.full_path);
	        ofn.lpstrFilter = "PPK files\0*.PPK\0All\0*.*\0";
	        ofn.lpstrTitle = "Select a file to decrypt";
	        ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
         
	        if( GetOpenFileName( &ofn ))
            {
                LPSTR fname;
                set_input_output:
                GetFullPathName( (LPCSTR)K.file1.full_path, sizeof(Buffer), (LPSTR)&Buffer[0], &fname );

                SetDlgItemText( hDlg, IDC_FILE_NAME, (LPSTR)&Buffer[0] );
                // use same foler for output
                if( fname[-1] == '\\' ) fname--;
                fname[0] = '\0';
                SetDlgItemText( hDlg, IDC_OUTPUT, (LPSTR)&Buffer[0] );

            }
            break;

        case IDC_BROWSE_OUTPUT:
            // Select destination
	        ZeroMemory( &ofn, sizeof(ofn));
	        ofn.lStructSize = sizeof(ofn);
	        ofn.hwndOwner = hDlg;
	        ofn.lpstrFile = (LPSTR)&K.file2.full_path[0];
	        ofn.lpstrFile[0] = '\0';
	        ofn.nMaxFile = sizeof(K.file2.full_path);
	        ofn.lpstrFilter = "All files\0*.*\0";
	        ofn.lpstrTitle = "Select destination";
	        ofn.Flags = OFN_PATHMUSTEXIST | OFN_NOREADONLYRETURN;
         
	        if( GetSaveFileName( &ofn ))
            {
                SetDlgItemText( hDlg, IDC_OUTPUT, (LPSTR)&K.file2.full_path[0] );
            }
            break;

        case IDOK:
            GetDlgItemText( hDlg, IDC_FILE_NAME, (LPSTR)&Buffer[0], sizeof(Buffer) );
            if( K.file1.Open( (char *)&Buffer[0], "rb" ))
                cc = PPK_FILE1_ERROR;
            else
            {
                size_t n;
                LPSTR fname;
                GetDlgItemText( hDlg, IDC_OUTPUT, (LPSTR)&Buffer[0], sizeof(Buffer) );
                if( Buffer[0] == '\0' )
                {
                    GetFullPathName( (LPCSTR)&K.file1.full_path[0], sizeof(Buffer), (LPSTR)&Buffer[0], &fname );
                    use_input_filename:
                    n = (unsigned long)strlen( (const char *)fname );

                    if( n > 4 && _stricmp( (const char *)&fname[n-4], ".ppk" ) == 0 )
                        fname[n - 4] = 0;    // Remove .PPK from file name
                    else
                        strcpy_s( (char *)fname, 20, "decrypted.$$$" );

                    cc = K.DecryptFile( &Buffer[0], 0 );
                }
                else
                {
                    HANDLE hFind;
                    WIN32_FIND_DATA FindFileData;
                    hFind = FindFirstFile( (LPCSTR)&Buffer[0], &FindFileData );
                    if( hFind != INVALID_HANDLE_VALUE )
                    {
                        FindClose( hFind );
                        if( FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY )
                        {
                            strcpy_s( (char *)&K.file2.full_path[0], sizeof(K.file2.full_path), (char *)&Buffer[0] );
                            strcat_s( (char *)&K.file2.full_path[0], sizeof(K.file2.full_path), "\\" );
                            strcat_s( (char *)&K.file2.full_path[0], sizeof(K.file2.full_path), (char *)K.file1.file_name );
                            GetFullPathName( (LPCSTR)&K.file2.full_path[0], sizeof(Buffer), (LPSTR)&Buffer[0], &fname );
                            goto use_input_filename;
                        }
                    }
                    strcpy_s( (char *)&K.file2.full_path[0], sizeof(K.file2.full_path), (char *)&Buffer[0] );
                    cc = K.DecryptFile( &Buffer[0], 1 );    // force output file name
                }
            }

            K.file1.Close();
            K.file2.Close();
            switch( cc )
            {
            case PPK_SUCCESS_RETURN:
                sprintf_s( (char *)&Buffer[0], sizeof(Buffer), "%s decrypted.", &K.file1.file_name[0] );
                StatusOut( hDlg, (LPSTR)&Buffer[0] );
                sprintf_s( (char *)&Buffer[0], sizeof(Buffer), "%s created successfully.", &K.file2.file_name[0] );
                StatusOut( hDlg, (LPSTR)&Buffer[0] );

                if( IsDlgButtonChecked( hDlg, IDC_DELETE_INPUT ))
                {
                    DeleteFile( (LPCSTR)&K.file1.full_path[0] );
                }
                break;

            case PPK_PASSWORD_NOT_VALID:
                StatusOut( hDlg, "Password is not valid." );
            case PPK_OPERATION_CANCELED:
			    break;

            case PPK_FILE1_ERROR:
                StatusOut( hDlg, (LPSTR)&K.file1.error_msg[0] );
			    break;

            case PPK_FILE2_ERROR:
                StatusOut( hDlg, (LPSTR)&K.file2.error_msg[0] );
			    break;
            }
	        //EndDialog(hDlg, (INT_PTR)cc);
		    return (INT_PTR)TRUE;

        case IDCANCEL:
	        EndDialog(hDlg, (INT_PTR)PPK_OPERATION_CANCELED);
			return (INT_PTR)FALSE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}

INT_PTR CALLBACK DisplayKeyDlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    CHAR buff[100];

	switch (message)
	{
	case WM_INITDIALOG:
        sprintf_s( buff, sizeof(buff), PUB_KEY_FMT, &UserKey.public_key_str[0], &UserKey.key_id[0] );
        SetDlgItemText( hDlg, IDC_KEY_ID, (LPCSTR)&buff[0]);
        SendMessage(hDlg, WM_SETICON, (WPARAM)FALSE, (LPARAM)hIcon);
        CheckDlgButton(hDlg, IDC_ADD_TO_LIST, TRUE );
		return (INT_PTR)TRUE;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
        case IDOK:
			EndDialog(hDlg, IsDlgButtonChecked( hDlg, IDC_ADD_TO_LIST ));
			return (INT_PTR)TRUE;

        case IDCANCEL:
			EndDialog(hDlg, FALSE);
			return (INT_PTR)TRUE;

        case IDC_CLIP_COPY:
            HWND hWnd = GetDlgItem(hDlg, IDC_KEY_ID);
	        SendMessage(hWnd, EM_SETSEL, 0, 65535L);
	        SendMessage(hWnd, WM_COPY, 0 , 0);
	        SendMessage(hWnd, EM_SETSEL, 0, 0);
			break;
		}
		break;
	}
	return (INT_PTR)FALSE;
}

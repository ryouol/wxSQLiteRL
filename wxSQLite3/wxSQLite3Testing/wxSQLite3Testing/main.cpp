#pragma once

#include "wx/wx.h"
#include "wx/grid.h"
#include "wx/wxsqlite3.h"
#include "hex.h"
#include "sha.h"
#include "filters.h"
#include "pch.h"
#include <random>
#include "main.h"

// consider account metadata for active state
//      MUST HAVE ONE CESdmin account that is enabled at all 
//      System account should never be deleted, but recommneded to disable after seeting up their own CEAdmin account
// need to have a feature where a CEAdmin can import a user table list for QoL
// also could support the ability to add an engineer account if somehow it is lost

// switch account feature... should only be possible when the app is not acquiring?


//CHANGE
// Hash without Salting
//std::string HashPassword(const std::string& password) {
//    CryptoPP::SHA256 hash;
//    std::string digest;
//
//    CryptoPP::StringSource ss(password, true,
//        new CryptoPP::HashFilter(hash,
//            new CryptoPP::HexEncoder(
//                new CryptoPP::StringSink(digest)
//            )
//        )
//    );
//
//    return digest;
//}

//Generate Salt
constexpr size_t SALT_LENGTH = 16;

std::string GenerateSalt(size_t length) {

    const std::string chars =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    std::random_device rd;
    std::mt19937 generator(rd()); 
    std::uniform_int_distribution<> distribution(0, chars.size() - 1);

    std::string salt; 
    for (size_t i = 0; i < length; ++i) {
        salt += chars[distribution(generator)]; 
    }

    return salt; 
}


// Hash the password with salt and return the hash appended with salt
std::string HashPasswordWithSalt(const std::string& password, const std::string& salt) {
    std::string saltedPassword = password + salt;
    CryptoPP::SHA256 hash;
    std::string digest;

    CryptoPP::StringSource(saltedPassword, true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(digest)
            )
        )
    );

    // Append salt to digest
    return digest + salt;
}

//END



enum SecurityLevel {
    CEQC = 1,    
    CERD = 2,
    CEAdmin = 3
};

class MyApp : public wxApp
{
public:
    virtual bool OnInit();
    virtual int OnExit();

    void UpdateAccountWithHashedPassword(const wxString& username, const wxString& password, int securityLevel);


private:
    wxSQLite3Database* db;
};

class LoginDialog : public wxDialog
{
public:
    LoginDialog(wxWindow* parent, wxSQLite3Database* db)
        : wxDialog(parent, wxID_ANY, "Login"), db(db), loginSuccess(false)
    {
        wxBoxSizer* sizer = new wxBoxSizer(wxVERTICAL);

        usernameCtrl = new wxTextCtrl(this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_PROCESS_ENTER);
        passwordCtrl = new wxTextCtrl(this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_PASSWORD | wxTE_PROCESS_ENTER);
        wxButton* okButton = new wxButton(this, wxID_OK);

        sizer->Add(new wxStaticText(this, wxID_ANY, "Username:"));
        sizer->Add(usernameCtrl);
        sizer->Add(new wxStaticText(this, wxID_ANY, "Password:"));
        sizer->Add(passwordCtrl);
        sizer->Add(okButton);

        SetSizerAndFit(sizer);

        okButton->Bind(wxEVT_BUTTON, &LoginDialog::OnOk, this);
        usernameCtrl->Bind(wxEVT_TEXT_ENTER, &LoginDialog::OnOk, this);
        passwordCtrl->Bind(wxEVT_TEXT_ENTER, &LoginDialog::OnOk, this);
        Bind(wxEVT_CLOSE_WINDOW, &LoginDialog::OnClose, this);
    }

    bool IsLoginSuccessful() const { return loginSuccess; }
    wxString GetUsername() const { return usernameCtrl->GetValue(); }
    int GetSecurityLevel() const { return loginSuccess ? securityLevel : 0; }

private:
    void OnOk(wxCommandEvent& event)
    {
        // wxString username = usernameCtrl->GetValue(); 
        // wxString password = passwordCtrl->GetValue();
        //wxSQLite3ResultSet set = db->ExecuteQuery("SELECT * FROM user WHERE username='" + username + "' AND password='" + password + "'");
        // //CHANGE
        //// std::string hashedInputPassword = HashPasswordWithSalt(std::string(password.mb_str()));
        //std::string storedHashWithSalt = std::string(set.GetAsString("password").mb_str(wxConvUTF8));

        //std::string salt = storedHashWithSalt.substr(storedHashWithSalt.length() - 16); // Replace SALT_LENGTH with the actual length of your salt
        // std::string hashedInputPassword = HashPasswordWithSalt(std::string(password.mb_str()), salt);

        // //if (set.NextRow()) {
        // //    loginSuccess = true;
        // //    securityLevel = set.GetInt("security_level");
        // //    EndModal(wxID_OK);
        // //}
        // //else {
        // //    wxMessageBox("Invalid username or password", "Error", wxOK | wxICON_ERROR);
        // //}

        // wxSQLite3ResultSet set = db->ExecuteQuery("SELECT * FROM user WHERE username='" + username + "'");

        // if (set.NextRow()) { // Ensure the stored hash includes the salt

        //     //std::string storedHash = std::string(set.GetAsString("password").mb_str(wxConvUTF8));

        //     std::string storedHashWithSalt = std::string(set.GetAsString("password").mb_str(wxConvUTF8));

        //     // Assuming the salt is appended at the end of the hash and is 32 characters long
        //     std::string salt = storedHashWithSalt.substr(storedHashWithSalt.length() - 32);
        //     std::string storedHash = storedHashWithSalt.substr(0, storedHashWithSalt.length() - 32);

        //     std::string passwordStr = std::string(password.mb_str());
        //     std::string inputHashedWithSalt = HashPasswordWithSalt(passwordStr, salt);

        //     if (inputHashedWithSalt == storedHashWithSalt) {
        //         loginSuccess = true;
        //         securityLevel = set.GetInt("security_level");
        //  EndModal(wxID_OK);
        //    }
        //     else {
        //         wxMessageBox("Invalid username or password", "Error", wxOK | wxICON_ERROR);
        //     }
        // }
        // //CHANGES END
        // else {
        //     wxMessageBox("Invalid username or password", "Error", wxOK | wxICON_ERROR);
        // }




        wxString username = usernameCtrl->GetValue();
        wxString password = passwordCtrl->GetValue();


        // Check if username is one of the hardcoded accounts
        if (username == "engineer" || username == "system") {
            wxSQLite3ResultSet set = db->ExecuteQuery("SELECT * FROM user WHERE username='" + username + "'");
            if (set.NextRow()) {
                std::string storedPassword = std::string(set.GetAsString("password").mb_str(wxConvUTF8));
                if (password == storedPassword) {
                    loginSuccess = true;
                    securityLevel = set.GetInt("security_level");
                    EndModal(wxID_OK);
                } else {
                    wxMessageBox("Invalid username or password", "Error", wxOK | wxICON_ERROR);
                }

            } else {
                wxMessageBox("Invalid username or password", "Error", wxOK | wxICON_ERROR);
            }

        } else {

            //Extract salt, hash provided password, and compare 
            wxSQLite3ResultSet set = db->ExecuteQuery("SELECT * FROM user WHERE username='" + username + "'");
            if (set.NextRow()) {
                // Assuming the whole stored hash (including the salt) is in the "password" column
                std::string storedHashWithSalt = std::string(set.GetAsString("password").mb_str(wxConvUTF8));
                const size_t SALT_LENGTH = 16; //Salt length

                // Ensure the stored hash includes the salt
                if (storedHashWithSalt.length() > SALT_LENGTH) {
                    // Extract the salt from the end of the stored hash
                    std::string salt = storedHashWithSalt.substr(storedHashWithSalt.length() - SALT_LENGTH);

                    // Re-hash the input password using the extracted salt
                    std::string hashedInputPassword = HashPasswordWithSalt(std::string(password.mb_str()), salt);

                    // Check if the re-hashed password matches the stored hash
                    if (hashedInputPassword == storedHashWithSalt) {
                        loginSuccess = true;
                        securityLevel = set.GetInt("security_level");
                        EndModal(wxID_OK);
                    }
                    else {
                        wxMessageBox("Invalid username or password", "Error", wxOK | wxICON_ERROR);
                    }
                }
                else {
                    // The stored password hash format is unexpected
                    wxMessageBox("Authentication error", "Error", wxOK | wxICON_ERROR);
                }
            }
            else {
                wxMessageBox("Invalid username or password", "Error", wxOK | wxICON_ERROR);
            }


        }

    }

    void OnClose(wxCloseEvent& event)
    {
        if (!loginSuccess) {
            // If the user closes the dialog without a successful login, end the modal with wxID_CANCEL
            EndModal(wxID_CANCEL);
        }
    }

    wxSQLite3Database* db;
    wxTextCtrl* usernameCtrl;
    wxTextCtrl* passwordCtrl;
    bool loginSuccess;
    int securityLevel;

};

wxString SecurityLevelToString(SecurityLevel level) {
    switch (level) {
    case CEQC: return "CEQC";
    case CERD: return "CERD";
    case CEAdmin: return "CEAdmin";
    default: return "";
    }
}

SecurityLevel StringToSecurityLevel(const wxString& str) {
    if (str == "CEQC") return CEQC;
    if (str == "CERD") return CERD;
    if (str == "CEAdmin") return CEAdmin;
    throw std::invalid_argument("Invalid security level");
}

class CreateAccountDialog : public wxDialog
{
public:
    CreateAccountDialog(wxWindow* parent, wxSQLite3Database* db, int securityLevel)
        : wxDialog(parent, wxID_ANY, "Create Account"), db(db), seclvl(securityLevel)
    {
        wxBoxSizer* sizer = new wxBoxSizer(wxVERTICAL);

        usernameCtrl = new wxTextCtrl(this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_PROCESS_ENTER);
        passwordCtrl = new wxTextCtrl(this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_PASSWORD | wxTE_PROCESS_ENTER);
        confirmPasswordCtrl = new wxTextCtrl(this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_PASSWORD | wxTE_PROCESS_ENTER);
        wxButton* okButton = new wxButton(this, wxID_OK);
        wxButton* cancelButton = new wxButton(this, wxID_CANCEL, "Cancel");

        wxArrayString choices;
        int currentUserSecurityLevel = seclvl;
        if (currentUserSecurityLevel >= CEQC) choices.Add("CEQC");
        if (currentUserSecurityLevel >= CERD) choices.Add("CERD");
        if (currentUserSecurityLevel >= CEAdmin) choices.Add("CEAdmin");
        securityLevelCtrl = new wxComboBox(this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, choices);
        sizer->Add(new wxStaticText(this, wxID_ANY, "Username:"));
        sizer->Add(usernameCtrl);
        sizer->Add(new wxStaticText(this, wxID_ANY, "Password:"));
        sizer->Add(passwordCtrl);
        sizer->Add(new wxStaticText(this, wxID_ANY, "Confirm Password:"));
        sizer->Add(confirmPasswordCtrl);
        sizer->Add(new wxStaticText(this, wxID_ANY, "Security Level:"));
        sizer->Add(securityLevelCtrl);
        sizer->Add(okButton);
        sizer->Add(cancelButton);


        SetSizerAndFit(sizer);

        okButton->Bind(wxEVT_BUTTON, &CreateAccountDialog::OnOk, this);
        cancelButton->Bind(wxEVT_BUTTON, &CreateAccountDialog::OnCancel, this);
        usernameCtrl->Bind(wxEVT_TEXT_ENTER, &CreateAccountDialog::OnOk, this);
        usernameCtrl->Bind(wxEVT_CHAR, &CreateAccountDialog::OnUsernameChar, this);
        passwordCtrl->Bind(wxEVT_TEXT_ENTER, &CreateAccountDialog::OnOk, this);

        //CHANGE<< 
      //  std::string username = std::string(usernameCtrl->GetValue().mb_str());
      //  std::string password = std::string(passwordCtrl->GetValue().mb_str());

      //  // Hash the password 
      //  std::string salt = GenerateSalt(16); 
      //  std::string passwordStr = std::string(passwordCtrl->GetValue().mb_str());
      //  std::string hashedPassword = HashPasswordWithSalt(passwordStr, salt); // Updated to use the modified HashPassword function

      //  // Store `username`, `hashedPassword` in the database instead of the plain password
      //wxSQLite3Statement stmt = db->PrepareStatement("INSERT INTO user (username, password, security_level) VALUES (?, ?, ?)");
      //  stmt.Bind(1, wxString(username.c_str(), wxConvUTF8));
      //  stmt.Bind(2, wxString(hashedPassword.c_str(), wxConvUTF8));
      // 
      //  stmt.Bind(3, (int)securityLevel); // Ensure securityLevel has been correctly defined and obtained
      //  stmt.ExecuteUpdate();

        // END
    }

private:
    void OnOk(wxCommandEvent& event)
    {
        wxString username = usernameCtrl->GetValue();
        wxString password = passwordCtrl->GetValue();
        wxString confirmPassword = confirmPasswordCtrl->GetValue();
        SecurityLevel securityLevel = StringToSecurityLevel(securityLevelCtrl->GetValue());

        if (password.length() < 6) {
            wxMessageBox("Password must be at least 6 characters", "Error", wxOK | wxICON_ERROR);
            return;
        }

        if (password != confirmPassword) {
            wxMessageBox("Passwords do not match", "Error", wxOK | wxICON_ERROR);
            return;
        }

        if (username.length() < 3 || !wxIsalpha(username[0])) {
            wxMessageBox("Username must be at least 3 characters and start with a letter", "Error", wxOK | wxICON_ERROR);
            return;
        }

        for (wxString::const_iterator it = username.begin(); it != username.end(); ++it) {
            if (!wxIsalnum(*it) && *it != '_' && *it != '-') {
                wxMessageBox("Username can only contain letters, numbers, underscores, and hyphens", "Error", wxOK | wxICON_ERROR);
                return;
            }
        }

        // Check for duplicate usernames
        wxSQLite3ResultSet set = db->ExecuteQuery("SELECT * FROM user WHERE username='" + username + "'");
        if (set.NextRow()) {
            wxMessageBox("Username already exists", "Error", wxOK | wxICON_ERROR);
            return;
        }



        //std::string hashedPassword = HashPassword(std::string(password.mb_str()));

        //wxSQLite3Statement stmt = db->PrepareStatement("INSERT INTO user (username, password, security_level) VALUES (?, ?, ?)");
        //stmt.Bind(1, username);
        //stmt.Bind(2, wxString(hashedPassword.c_str(), wxConvUTF8));
        //stmt.Bind(3, (int)securityLevel);
        //stmt.ExecuteUpdate();



        //EndModal(wxID_OK);


        // Generate a salt and hash the password with it
        std::string salt = GenerateSalt(16); 
        std::string passwordStr = std::string(password.mb_str());
        std::string hashedPasswordWithSalt = HashPasswordWithSalt(passwordStr, salt); 

        // Store username and hashedPasswordWithSalt in the database
        wxSQLite3Statement stmt = db->PrepareStatement("INSERT INTO user (username, password, security_level) VALUES (?, ?, ?)");
       // stmt.Bind(1, wxString(username.c_str(), wxConvUTF8));
        stmt.Bind(1, wxString::FromUTF8(username.c_str()));
        stmt.Bind(2, wxString(hashedPasswordWithSalt.c_str(), wxConvUTF8));
        stmt.Bind(3, (int)securityLevel);
        stmt.ExecuteUpdate();

        EndModal(wxID_OK);


    }

    void OnCancel(wxCommandEvent& event)
    {
        EndModal(wxID_CANCEL);
    }

    void OnUsernameChar(wxKeyEvent& event)
    {
        int keyCode = event.GetKeyCode();

        // Allow control characters
        if (keyCode < WXK_SPACE || keyCode == WXK_DELETE || wxIsprint(keyCode)) {
            event.Skip();
            return;
        }

        // Allow letters always
        if (wxIsalpha(keyCode)) {
            event.Skip();
            return;
        }

        // Allow digits, underscore and hyphen only after the first character
        if (usernameCtrl->GetInsertionPoint() > 0 && (wxIsdigit(keyCode) || keyCode == '_' || keyCode == '-')) {
            event.Skip();
            return;
        }
    }



    wxSQLite3Database* db;
    int seclvl;
    wxTextCtrl* usernameCtrl;
    wxTextCtrl* passwordCtrl;
    wxTextCtrl* confirmPasswordCtrl;
    wxComboBox* securityLevelCtrl;
};

class UserGrid : public wxGrid
{
public:
    UserGrid(wxWindow* parent, wxSQLite3Database* db, int securityLevel)
        : wxGrid(parent, wxID_ANY), db(db), securityLevel(securityLevel)
    {
        CreateGrid(0, securityLevel >= 3 ? 3 : 2);
        SetColLabelValue(0, "Username");
        SetColLabelValue(1, "Security Level");
        if (securityLevel >= 3) {
            SetColLabelValue(2, "Delete");
        }

        wxSQLite3ResultSet set = db->ExecuteQuery("SELECT * FROM user WHERE username != 'engineer'");
        while (set.NextRow()) {
            int row = GetNumberRows();
            AppendRows(1);
            SetCellValue(row, 0, set.GetAsString("username"));
            SetCellValue(row, 1, SecurityLevelToString(static_cast<SecurityLevel>(set.GetInt("security_level"))));
            if (securityLevel >= 3) {
                SetCellValue(row, 2, "Delete");
            }
        }

        Bind(wxEVT_GRID_CELL_LEFT_CLICK, &UserGrid::OnCellLeftClick, this);
    }

private:
    void OnCellLeftClick(wxGridEvent& event)
    {
        if (securityLevel >= 3 && event.GetCol() == 2) {
            wxString username = GetCellValue(event.GetRow(), 0);
            db->ExecuteUpdate("DELETE FROM user WHERE username='" + username + "'");
            DeleteRows(event.GetRow());
        }
    }

    wxSQLite3Database* db;
    int securityLevel;
};

class UserFrame : public wxFrame
{
public:
    UserFrame(wxSQLite3Database* db, int securityLevel)
        : wxFrame(NULL, wxID_ANY, "Users")
    {
        UserGrid* grid = new UserGrid(this, db, securityLevel);
        SetSizer(new wxBoxSizer(wxVERTICAL));
        GetSizer()->Add(grid, 1, wxEXPAND);
    }
};


class MyFrame : public wxFrame
{
public:
    MyFrame(wxSQLite3Database* db) : wxFrame(NULL, wxID_ANY, "My Frame"), db(db)
    {
        LoginDialog* dlg = new LoginDialog(this, db);
        if (dlg->ShowModal() != wxID_OK) {
            // The user has closed the login dialog without a successful login
            // Close the entire application
            Close(true);
        }
        else {
            // The user has logged in successfully
            // Retrieve the user's details
            wxString username = dlg->GetUsername();
            securityLevel = dlg->GetSecurityLevel();

            // Display the user's details
            SetTitle("Logged in as: " + username + ", Security level: " + wxString::Format("%d", securityLevel));
        }
        dlg->Destroy();

        wxMenu* menuFile = new wxMenu;
        menuFile->Append(ID_CreateAccount, "&Create Account...\tCtrl-N", "Create a new account");
        menuFile->Append(ID_DisplayUsers, "&Display Users...\tCtrl-D", "Display all users");
        wxMenuBar* menuBar = new wxMenuBar;
        menuBar->Append(menuFile, "&File");
        SetMenuBar(menuBar);

        Bind(wxEVT_MENU, &MyFrame::OnCreateAccount, this, ID_CreateAccount);
        Bind(wxEVT_MENU, &MyFrame::OnDisplayUsers, this, ID_DisplayUsers);

    }
private:
    wxSQLite3Database* db;
    int securityLevel;

    void OnCreateAccount(wxCommandEvent& event)
    {
        CreateAccountDialog* dlg = new CreateAccountDialog(this, db, securityLevel);
        dlg->ShowModal();
        dlg->Destroy();
    }

    void OnDisplayUsers(wxCommandEvent& event)
    {
        UserFrame* frame = new UserFrame(db, securityLevel);
        frame->Show(true);
    }

    enum
    {
        ID_CreateAccount = 1,
        ID_DisplayUsers
    };
};

IMPLEMENT_APP(MyApp)


// Change 
bool MyApp::OnInit()
{
    //// Create a new wxSQLite3Database object
    //db = new wxSQLite3Database();

    //// Open a new database
    //db->Open("myDatabase.db");

    //// Check if the user table exists
    //if (db->TableExists("user"))
    //{
    //    // The table exists, no need to create it
    //}
    //else
    //{
    //    // The table doesn't exist, create it
    //    db->ExecuteUpdate("CREATE TABLE user (username TEXT, password TEXT, security_level INTEGER)");

    //    
    //    // Insert the system user
    //    db->ExecuteUpdate("INSERT INTO user (username, password, security_level) VALUES ('engineer', '38078', 4)");

    //    // Insert the system user
    //    db->ExecuteUpdate("INSERT INTO user (username, password, security_level) VALUES ('system', 'manager', 3)");
    //}

    //// Create a new frame, passing the database object to it
    //MyFrame* frame = new MyFrame(db);
    //frame->Show(true);

    //return true;




    //// Adjusted Code for User Insertion
    //// 
    //    // Create a new wxSQLite3Database object
    //    db = new wxSQLite3Database();

    //    // Open a new database
    //    db->Open("myDatabase.db");

    //    // Check if the user table exists
    //    if (!db->TableExists("user"))
    //    {
    //        // The table doesn't exist, create it
    //        db->ExecuteUpdate("CREATE TABLE user (username TEXT, password TEXT, security_level INTEGER)");
    //    }

    //    // Check and insert the engineer user if it doesn't exist
    //    wxSQLite3ResultSet rsEngineer = db->ExecuteQuery("SELECT * FROM user WHERE username='engineer'");
    //    if (!rsEngineer.NextRow())
    //    {
    //        std::string engineerPassword = "38078"; 
    //        std::string salt = GenerateSalt(SALT_LENGTH);
    //        std::string hashedPassword = HashPasswordWithSalt(engineerPassword, salt);

    //        // Prepare the SQL statement for insertion
    //        wxSQLite3Statement stmt = db->PrepareStatement("INSERT INTO user (username, password, security_level) VALUES (?, ?, 4)");
    //        stmt.Bind(1, "engineer");
    //        stmt.Bind(2, wxString(hashedPassword.c_str(), wxConvUTF8));
    //        stmt.ExecuteUpdate(); 
    //    }
    //    rsEngineer.Finalize();

    //    // Check and insert the system user if it doesn't exist
    //    wxSQLite3ResultSet rsSystem = db->ExecuteQuery("SELECT * FROM user WHERE username='system'");
    //    if (!rsSystem.NextRow())
    //    {
    //        std::string systemPassword = "manager"; 
    //        std::string salt = GenerateSalt(SALT_LENGTH);
    //        std::string hashedPassword = HashPasswordWithSalt(systemPassword, salt);

    //        // Prepare the SQL statement for insertion
    //        wxSQLite3Statement stmt = db->PrepareStatement("INSERT INTO user (username, password, security_level) VALUES (?, ?, 3)");
    //        stmt.Bind(1, "system");
    //        stmt.Bind(2, wxString(hashedPassword.c_str(), wxConvUTF8));
    //        stmt.ExecuteUpdate(); 
    //    }
    //    rsSystem.Finalize();

    //    // Proceed with frame creation as before
    //    MyFrame* frame = new MyFrame(db);
    //    frame->Show(true);

    //    return true;
    //





    db = new wxSQLite3Database();
    db->Open("myDatabase.db");

    if (!db->TableExists("user"))
    {
        db->ExecuteUpdate("CREATE TABLE user (username TEXT, password TEXT, security_level INTEGER)");
    }

    // Update or insert the 'engineer' account with a hashed password
    wxString engineerUsername = "engineer";
    wxString engineerPassword = "38078"; // Set the initial password for the engineer account
    UpdateAccountWithHashedPassword(engineerUsername, engineerPassword, 4); // Assuming '4' is the security level for 'engineer'

    // Update or insert the 'system' account with a hashed password
    wxString systemUsername = "system";
    wxString systemPassword = "manager"; // Set the initial password for the system account
    UpdateAccountWithHashedPassword(systemUsername, systemPassword, 3); // Assuming '3' is the security level for 'system'

    // Continue with frame creation...
    MyFrame* frame = new MyFrame(db);
    frame->Show(true);
    return true;


}



void MyApp::UpdateAccountWithHashedPassword(const wxString& username, const wxString& password, int securityLevel)
{
    wxSQLite3ResultSet rs = db->ExecuteQuery("SELECT * FROM user WHERE username='" + username + "'");
    if (!rs.NextRow())
    {
        std::string salt = GenerateSalt(SALT_LENGTH);
        std::string hashedPassword = HashPasswordWithSalt(password.ToStdString(), salt);
        wxSQLite3Statement stmt = db->PrepareStatement("INSERT INTO user (username, password, security_level) VALUES (?, ?, ?)");
        stmt.Bind(1, username);
        stmt.Bind(2, wxString(hashedPassword.c_str(), wxConvUTF8));
        stmt.Bind(3, securityLevel);
        stmt.ExecuteUpdate();
    }
    rs.Finalize();
}

int MyApp::OnExit()
{
    // Close the database
    //db->Close();

    // Delete the wxSQLite3Database object
    //delete db;

    // Delete the database file
    //wxRemoveFile("myDatabase.db");

    return 0;
}

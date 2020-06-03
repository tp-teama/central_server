#include "CentralServer.h"

bool SymbolCheck(char c);

void CentralServer::StartServer() {
    boost::asio::io_service svc;
    tcp::acceptor a(svc);
    a.open(tcp::v4());
    a.set_option(tcp::acceptor::reuse_address(true));
    a.bind({{}, 5000});
    a.listen(5);
    std::shared_ptr<tcp::socket> response_address;

    using session = std::shared_ptr<tcp::socket>;
    std::function<void()>        do_accept;
    std::function<void(session)> do_session;

    do_session = [&](session s) {
        auto buf = std::make_shared<std::vector<char>>(1024);
        s->async_read_some(boost::asio::buffer(*buf), [&,s,buf](boost::system::error_code ec, size_t bytes) {
            if (ec) {
                std::cerr << "read failed: " << ec.message() << "\n";
            }
            else {
                std::cout << "Got message from " << s->remote_endpoint(ec) << ": " ;
                std::string msg = std::string(buf->data(), bytes);

                std::string str = buf->data();
                int i = 0;
                while (!SymbolCheck(str[str.length() - 1 - i])){
                    i++;
                }
                std::string new_str = str.substr(0, str.length() - i);
                std::cout << std::endl << "new str is :  " << new_str << "|" << "i is " << i << std::endl;
                std::cout << "symbol chack is " << (new_str[new_str.length() - 1]) << (new_str[new_str.length() - 2]) << (new_str[new_str.length() - 0]) << new_str[0] << "------------------";
                string resp = ParseRequest(new_str);

                if (ec) {
                    std::cerr << "endpoint failed: " << ec.message() << "\n";
                } else {
                    SendBack(response_address, resp);
                }
                do_session(s);

            }

        });
    };

    do_accept = [&] {
        auto s = std::make_shared<session::element_type>(svc);
        a.async_accept(*s, [&,s](boost::system::error_code ec) {
            if (ec)
                std::cerr << "accept failed: " << ec.message() << "\n";
            else {
                response_address = s;
                do_session(s);
                do_accept();
            }
        });
    };

    do_accept(); // кик
    svc.run();   // ждем закрытия
}

void CentralServer::SendBack(std::shared_ptr<tcp::socket> resp, string body) {

    async_write(*resp, boost::asio::buffer(body), [&, resp, body](boost::system::error_code ec, size_t) {
        if (ec) std::cerr << "write failed: " << ec.message() << "\n";
    });
}

string CentralServer::AddUser(string ip, string username, string password) {
    if (ip == ""){
        return "";
    }

    std::map<o_uuid, User>::iterator it = users.begin();
    User user;

    while (it != users.end())
    {
        if (it->second.username == username) {
            return "";
        }
        it++;
    }

    User u;
    u.public_key = password;
    //todo: add public key
    u.ip_adress = ip;
    u.username = username;
    u.is_auth = false;
    o_uuid user_id = b_uuid::random_generator()();
    users.insert(pair<o_uuid, User>(user_id, u));

    string string_id = b_uuid::to_string(user_id);
    return string_id;
}

bool CentralServer::UpdateIpAdress(o_uuid user_id, string newIp) {
    if (newIp == "" || users.find(user_id) == users.end()){
        return false;
    }

    std::map<o_uuid, User>::iterator it = users.find(user_id);
    it->second.ip_adress = newIp;
    return true;
}

string CentralServer::Login(string username, string password) {
    if (password == "" || username == ""){
        return "";
    }

    std::map<o_uuid, User>::iterator it = users.begin();
    User u;

    while (it != users.end())
    {
        if (it->second.username == username) {
            if (it->second.public_key == password && it->second.is_auth != true){
                it->second.is_auth = true;
                string id = b_uuid::to_string(it->first);
                return id;
            } else {
                return "";
            }
        }
        it++;
    }

    return "";
}

bool CentralServer::Logout(o_uuid user_id) {
    std::map<o_uuid, User>::iterator u = users.find(user_id);
    if (u == users.end()){
        return false;
    }

    if (u->second.is_auth == false) {
        return false;
    } else {
        u->second.ip_adress = "0";
        u->second.is_auth = false;
        return true;
    }
}

int CentralServer::IsAuth(o_uuid user_id) {
    std::map<o_uuid, User>::iterator u = users.find(user_id);
    if (u == users.end()){
        return -1;
    }

    if (u->second.is_auth == true) {
        return 1;
    } else {
        return 0;
    }
}

User CentralServer::GetUsersByUsername(string username) {
    if (username == ""){
        return User{};
    }

    std::map<o_uuid, User>::iterator it = users.begin();
    User u;

    while (it != users.end())
    {
        if (it->second.username == username) {
            u = it->second;
            u.user_id = it->first;
            return u;
        }
        it++;
    }

    return User{};
}

User CentralServer::GetUserByID(o_uuid user_id) {
    if (users.find(user_id) == users.end()){
        return User{};
    }

    User u = users.find(user_id)->second;
    u.user_id = user_id;
    return u;
}

bool CentralServer::JoinChat(string chatname, string password, o_uuid user_id) {
    if ((chatname == "") || (password == "")){
        return false;
    }

    if (chats.find(chatname) == chats.end()){
        return false;
    }

    if (users.find(user_id) == users.end()){
        return false;
    }

    Chat chat = chats.find(chatname)->second;

    if (chat.password != password){
        return false;
    }


    std::map<string, Chat>::iterator it = chats.find(chatname);
    vector<o_uuid> us = it->second.v_users;
    for(std::vector<o_uuid>::iterator its = us.begin(); its != us.end(); ++its) {
        if (*its == user_id){
            return false;
        }
    }

    us.push_back(user_id);
    it->second.v_users = us;

    return true;
}

bool CentralServer::CreateChat(string chatname, string password, o_uuid user_id) {
    if ((chatname == "") || (password == "")){
        return false;
    }

    if (chats.find(chatname) != chats.end()){
        return false;
    }

    if (users.find(user_id) == users.end()){
        return false;
    }

    Chat c;
    c.name = chatname;
    c.password = password;
    c.v_users.push_back(user_id);
    chats.insert(pair<string, Chat>(chatname, c));

    return true;
}

string CentralServer::GetChatPort(string chatname, o_uuid id) {
    if (chatname == ""){
        return "0";
    }

    if (chats.find(chatname) == chats.end()){
        return "0";
    }

    if (users.find(id) == users.end()){
        return "0";
    }

    Chat c = chats.find(chatname)->second;
    vector<o_uuid> us = c.v_users;

    for(std::vector<o_uuid>::iterator it = us.begin(); it != us.end(); ++it) {
        if (*it != id){
            o_uuid id = *it;
            std::map<o_uuid, User>::iterator us = users.find(id);
            if (us == users.end()){
                return "0";
            }

            return us->second.ip_adress;
        }
    }

    return "0";
}

string CentralServer::ParseRequest(string req) {
//command, username, password, user_id, ip
    req = req + " ";
    cout << "parsing smth";
    string username = "", ip = "", password = "", command = "", user_id = "", chat_name = "";
    if (req.find("username:") != string::npos){
        int pos;
        pos = req.find("username:");
        string new_str = req.substr(pos, req.size());
        username = new_str.substr(sizeof("username"), new_str.find(" ") - sizeof("username"));
    }
    if (req.find("chat_name:") != string::npos){
        int pos;
        pos = req.find("chat_name:");
        string new_str = req.substr(pos, req.size());
        chat_name = new_str.substr(sizeof("chat_name"), new_str.find(" ") - sizeof("chat_name"));
    }
    if (req.find("command:") != string::npos){
        int pos;
        pos = req.find("command:");
        string new_str = req.substr(pos, req.size());
        command = new_str.substr(sizeof("command"), new_str.find(" ") - sizeof("command"));
    }
    if (req.find("password:") != string::npos){
        int pos;
        pos = req.find("password:");
        string new_str = req.substr(pos, req.size());
        password = new_str.substr(sizeof("password"), new_str.find(" ") - sizeof("password"));
    }
    if (req.find("user_id:") != string::npos){
        int pos;
        pos = req.find("user_id:");
        string new_str = req.substr(pos, req.size());
        user_id = new_str.substr(sizeof("user_id"), new_str.find(" ") - sizeof("user_id"));
    }
    if (req.find("ip:") != string::npos){
        int pos;
        pos = req.find("ip:");
        string new_str = req.substr(pos, req.size());
        ip = new_str.substr(sizeof("ip"), new_str.find(" ") - sizeof("ip"));
    }

    cout << "user :" << username << " pass :" << password << " comm :" << command << " chat_name :" << chat_name << endl;
    string response;

    if (command == "add_user"){
        cout << "start adding";
        string id = AddUser(ip, username, password);
        response = "user_id:" + id;
        cout << "adding user with id  " << id;
    } else if (command == "update_ip"){
        o_uuid uuid_id = boost::lexical_cast<o_uuid>(user_id);
        bool res = UpdateIpAdress(uuid_id, ip);
        if (res) {
            response = "res:true";
        } else {
            response = "res:false";
        }
        cout << "updating ip";
    } else if (command == "login"){
        cout << "loging";
        string res = Login(username, password);
        response = "user_id:" + res;
        cout << "login";
    } else if (command == "logout"){
        o_uuid uuid_id = boost::lexical_cast<o_uuid>(user_id);
        bool res = Logout(uuid_id);
        if (res) {
            response = "res:true";
        } else {
            response = "res:false";
        }
        cout << "logout";
    } else if (command == "get_user_by_id"){
        cout << "user_id in string:   " << user_id << "|" << endl;
        o_uuid uuid_id = boost::lexical_cast<o_uuid>(user_id);
        User u = GetUserByID(uuid_id);
        string auth;
        if (u.is_auth) {
            auth = "true";
        } else {
            auth = "false";
        }
        response = "user_id:" + b_uuid::to_string(u.user_id) + " username:" + u.username + " is_auth:" + auth + " ip:" + u.ip_adress;
        cout << "get by id" << "  :   " << uuid_id;
    } else if (command == "get_user_by_username"){
        User u = GetUsersByUsername(username);
        string auth;
        if (u.is_auth) {
            auth = "true";
        } else {
            auth = "false";
        }
        std::cout << "uuid " << u.user_id << std::endl;
        response = "user_id:" + b_uuid::to_string(u.user_id) + " username:" + u.username + " is_auth:" + auth + " ip:" + u.ip_adress;
        cout << "get by username";
    } else if (command == "is_auth"){
        o_uuid uuid_id = boost::lexical_cast<o_uuid>(user_id);
        int res = IsAuth(uuid_id);
        if (res == 1) {
            response = "res:true";
        } else if (res == 0){
            response = "res:false";
        } else {
            response = "res:not_found";
        }
        cout << "is_auth";
    } else if (command == "join_chat") {
        o_uuid uuid_id = boost::lexical_cast<o_uuid>(user_id);
        bool res = JoinChat(chat_name, password, uuid_id);
        if (res) {
            response = "res:true";
        } else {
            response = "res:false";
        }
        cout << "join chat";
    } else if (command == "create_chat") {
        o_uuid uuid_id = boost::lexical_cast<o_uuid>(user_id);
        bool res = CreateChat(chat_name, password, uuid_id);
        if (res) {
            response = "res:true";
        } else {
            response = "res:false";
        }
        cout << "create chat";
    } else if (command == "get_chat_name") {
        o_uuid uuid_id = boost::lexical_cast<o_uuid>(user_id);
        string res = GetChatPort(chat_name, uuid_id);
        response = "ip:" + res;
        cout << "get name chat";
    } else {
        cout << "default" << endl;
    }

    cout << "end";

    return response;
}

bool SymbolCheck(char c){
    if (isalnum(c)){
        return true;
    }
    if (c == '-' || c == '_'){
        return true;
    }
    return false;
}

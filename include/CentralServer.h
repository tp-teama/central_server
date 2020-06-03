#include <iostream>
#include <string>
#include <map>
#include <boost/uuid/uuid.hpp>            // uuid class
#include <boost/uuid/uuid_generators.hpp> // generators
#include <boost/uuid/uuid_io.hpp>         // streaming operators etc.
#include <boost/asio.hpp>
#include <iostream>
#include <vector>
#include <boost/lexical_cast.hpp>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>


using boost::asio::ip::tcp;
using boost::system::error_code;
using boost::asio::streambuf;


using namespace std;

namespace b_uuid = boost::uuids;
typedef boost::uuids::uuid o_uuid;

struct User{
    o_uuid user_id;
    string public_key;
    string ip_adress;
    string username;
    bool is_auth;
};

struct Chat{
    string name;
    string password;
    vector<o_uuid> v_users;
};

class CentralServer{
public:
    void StartServer();
    string AddUser(string ip, string username, string password);
    bool UpdateIpAdress(o_uuid user_id, string newIp);
    string ParseRequest(string req);
    void SendBack(std::shared_ptr<tcp::socket> resp, string body);
    string Login(string username, string password);
    bool Logout(o_uuid user_id);
    int IsAuth(o_uuid user_id);
    User GetUsersByUsername(string username);
    User GetUserByID(o_uuid user_id);
    bool JoinChat(string chatname, string password, o_uuid user_id);
    bool CreateChat(string chatname, string password, o_uuid user_id);
    string GetChatPort(string chatname, o_uuid id);
private:
    map<o_uuid , User> users;
    map<string, Chat> chats;
};
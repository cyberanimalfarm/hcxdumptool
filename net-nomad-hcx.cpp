#include <string>
#include <fstream>
#include <iostream>
#include <bitset>
#include <chrono>
#include <iomanip>
#include <fmt/core.h>
#include "include/cxxopts.hpp"
#include "include/hcxdumptool.h"
#include "hcxpcapngtool/include/pcapngtool/hcxpcapngtool.h"

using namespace std;

vector<string> valid_channels = {"1a","2a","3a","4a","5a","6a","7a","8a","9a","10a","11a","12a","13a","14a","34b","36b","38b","40b","42b","44b","46b","48b","52b","56b","60b","64b","100b","104b","108b","112b","116b","120b","124b","128b","132b","136b","140b","144b","149b","153b","157b","161b","165b"};
vector<string> LB_channels = {"1a","2a","3a","4a","5a","6a","7a","8a","9a","10a","11a","12a","13a","14a"}; 
vector<string> HB_channels = {"34b","36b","38b","40b","42b","44b","46b","48b","52b","56b","60b","64b","100b","104b","108b","112b","116b","120b","124b","128b","132b","136b","140b","144b","149b","153b","157b","161b","165b"};


// simple string remove
void removeCharsFromString(string &str, string charsToRemove) {
   for ( unsigned int i = 0; i < strlen(charsToRemove.c_str()); ++i ) {
      str.erase( remove(str.begin(), str.end(), charsToRemove[i]), str.end() );
   }
}

// Read target macs from a file
std::vector<std::string> readLinesFromFile(const std::string &filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open the file!");
    }

    std::vector<std::string> lines;
    std::string line;
    while (std::getline(file, line)) {
        lines.push_back(line);
    }

    file.close();
    return lines;
}


// Join a vector<string> into a comma-delimitted string
string join_string(vector<string> vec) {
    string s;
    int c = 0;
    for (std::vector<std::string>::const_iterator i = vec.begin(); i != vec.end(); ++i) {
        if(c > 0) {
            s += ","+*i;
        } else {
            s += *i;
        }
        c++;
    }
    return s;
}

// Check if the mac is valid (and remove delimiters, if we have them)
bool validateMAC(std::string &mac) {
    std::regex macPattern("^([0-9A-Fa-f]{2}[:-]?){5}([0-9A-Fa-f]{2})$");
    if(!std::regex_match(mac, macPattern)) {
        return false;
    }
    removeCharsFromString(mac, ":-");
    return true;
}

std::string GetCurrentTimeForFileName()
{
    auto time = std::time(nullptr);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time), "%Y%m%d-%T");
    auto s = ss.str();
    std::replace(s.begin(), s.end(), ':', '-');
    return s;
}

int main(int argc, char **argv) {

    cxxopts::Options options("NET NOMAD HCX", "WiFi attack tool based on the HCX Dump Tool engine.");
    options.add_options()
        ("i,interface", "WiFi Interface Ex: wlan1", cxxopts::value<string>())
        ("t,targets", "Targets Ex: 11:22:33:44:55:66 77:88:99:44:55:66",cxxopts::value<vector<string>>())
        ("f,file", "Path to file containing target MAC addresses, one per line", cxxopts::value<string>())
        ("c,channels", "Channels Ex: 1a,6a,11a OR [LB/HB/ALL] | Default: 1a,6a,11a",cxxopts::value<vector<string>>())
        ("n,notar", "Instructs NN to NOT create Tarfile of all output files | Default: false")
        ("p,pcapng", "Instructs NN to produce PCAP-NG file | Default: false")
        ("r,clear", "Instructs NN to clear screen before printing a new status. Do not use with jq. | Default: false")
        ("h,help", "Display Help")
    ;

    options.allow_unrecognised_options();
    options.parse_positional({"interface", "targets"});
    options.positional_help("<interface> <target> <target> <target>...");
    

    auto parser = options.parse(argc, argv);

    if (parser.count("help")) {
        std::cout << options.help() << std::endl;

        exit(0);
    }

    // Check for conflicting arguments
    if (parser.count("file") && parser.count("targets")) {
        std::cout << "{{\"ERROR\":{{\"message\":\"Conflicting arguments: cannot use both -f/--file and -t/--targets together.\",\"fatal\":true}}}}" << std::endl;
        exit(1);
    }

    // Declare targets variable
    vector<string> targets;

    // Check for targets option
    if (parser.count("targets")) {
        targets = parser["targets"].as<vector<string>>();
    }

    // Check for file option
    if (parser.count("file")) {
        std::string filePath = parser["file"].as<string>();
        try {
            targets = readLinesFromFile(filePath);  // Set the targets vector with MAC addresses from the file
        } catch (const std::exception &e) {
            std::cout << "{{\"ERROR\":{{\"message\":\"" << e.what() << "\",\"fatal\":true}}}}" << std::endl;
            exit(1);
        }
    }

    // Ensure that targets are provided
    if (targets.empty()) {
        std::cout << "{{\"ERROR\":{{\"message\":\"No targets provided. Use either -t/--targets or -f/--file.\",\"fatal\":true}}}}" << std::endl;
        exit(1);
    }

    if(targets.size() > 50) {
        cout << "{{\"ERROR\":{{\"message\":\"Too many targets. Max is 50\",\"fatal\":true}}}}" << endl;
        exit(1);
    }

    
    string iface = parser["interface"].as<string>();
    
   
    vector<string> channels;
    if (parser.count("channels")) {
        channels = parser["channels"].as<vector<string>>();
        if(channels[0] == "LB")
            channels = LB_channels;
        if(channels[0] == "HB")
            channels = HB_channels;
        if(channels[0] == "ALL")
            channels = valid_channels; // eek
    } else {
        channels = {"1a","6a","11a"}; 
    }

    // Validate channels
    for (string channel : channels) {
        if (std::find(valid_channels.begin(), valid_channels.end(), channel) != valid_channels.end())
            continue;
        string error_json = fmt::format("{{\"ERROR\":{{\"message\":\"Invalid Channel: {} \",\"fatal\":true}}}}", channel);
        cout << error_json << endl;
        std::cout << options.help() << std::endl;
        exit(0);
    }

    // Validate Targets
    for (string &mac : targets) {
        if(!validateMAC(mac)){
            string error_json = fmt::format("{{\"ERROR\":{{\"message\":\"Invalid MAC: {} \",\"fatal\":true}}}}", mac);
            cout << error_json << endl;
            std::cout << options.help() << std::endl;
            exit(0);
        }
    }


    // Final args
    bool notar = parser["notar"].as<bool>();
    bool tar = !notar;
    bool pcapng = parser["pcapng"].as<bool>();
    bool clear = parser["clear"].as<bool>();


    // Generate Timestamp for filename
    string filename = "NN-" + GetCurrentTimeForFileName();

    // Print args in JSON
    string args = fmt::format("{{\"ARGS\": {{ \"interface\": \"{}\",\"file_prefix\": \"{}\",\"targets\": \"{}\", \"channels\": \"{}\",\"tarfile\": \"{}\",\"pcapng\": \"{}\"}}}}", iface, filename, join_string(targets).c_str(), join_string(channels).c_str(), tar, pcapng);
    cout << args << endl;

    // Write the args to a file
    std::ofstream out(filename + ".args");
    out << args;
    out.close();
    

    pcap_buffer_t* result = hcx(iface.c_str(), join_string(targets).c_str(), join_string(channels).c_str(), clear);
    
    unsigned long p_buffer_size = result->len;
    unsigned char* p_buffer = result->result;

    // int pcapngtool(char* prefixname, uint8_t* pcap_buffer, size_t len, bool writePcapNG, bool tarFiles)
    int pcap_result = pcapngtool(filename.c_str(), p_buffer, p_buffer_size, pcapng, tar);
    
    return 0;
}
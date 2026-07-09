#include <iostream>
#include <set>
#include <string>
#include <filesystem>
#include <sstream>
#include <Windows.h>

using namespace std;
using std::filesystem::recursive_directory_iterator;
namespace fs = std::filesystem;

void search(std::string cur_dir) {

    set<string>list({ "micro","zepto","cerber","locky","cerber3","cryp1","mole","onion","axx","osiris","crypz","crypt","locked","odin","ccc","cerber2","sage","globe","exx","good","wallet","1txt","decrypt2017","encrypt","ezz","zzzzz","MERRY","enciphered","r5a","aesir","aesir","ecc","enigma","cryptowall","encrypted","loli","breaking_bad","coded","ha3","damage","wcry","lol!","cryptolocker","dharma","MRCR1","sexy","crjoker","fantom","keybtc@inbox_com","rrk","legion","kratos","LeChiffre","kraken","zcrypt","maya","file0locked","crinf","serp","potato","ytbl","surprise","angelamerkel","windows10","lesli","serpent","PEGS1","dale","pdcr","zzz","xyz","1cbu1","venusf","coverton","thor","rnsmwr","evillock","R16m01d05","wflx","nuclear55","darkness","encr","rekt","kernel_time","zyklon","Dexter","locklock","cry","VforVendetta","btc","raid10","dCrypt","zorro","AngleWare","EnCiPhErEd","purge","realfs0ciety@sigaint.org.fs0ciety","shit","atlas","crypted","padcrypt","xxx","hush","vbransom","cryeye","unavailable","braincrypt","fucked","crypte","_AiraCropEncrypted","stn","paym","spora","RARE1","alcatraz","pzdc","aaa","ttt","odcodc","vvv","ruby","pays","comrade","antihacker2017","herbst","szf","rekt","kernel_time","zyklon","Dexter","locklock","cry","VforVendetta","btc","raid10","dCrypt","zorro","AngleWare","EnCiPhErEd","purge","realfs0ciety@sigaint.org.fs0ciety","shit","atlas","exotic","crypted","padcrypt","xxx","hush","vbransom","RMCM1","cryeye","unavailable","braincrypt","fucked","crypte","_AiraCropEncrypted","stn","paym","spora","RARE1","crptrgr","kkk","rdm","BarRax","vindows","helpmeencedfiles","hnumkhotep","CCCRRRPPP","kyra","fun","rip","73i87A","bitstak","kernel_complete","payrms","a5zfn","perl","noproblemwedecfiles","lcked","p5tkjw","paymst","magic","payms","d4nk","SecureCrypted","kostya","lovewindows","madebyadam","powerfulldecrypt","gefickt","kernel_pid","ifuckedyou","grt","conficker","edgel","PoAr2w","oops","adk","Whereisyourfiles","czvxce","theworldisyours","razy","rmd","kimcilware","paymrss","dxxd","pec","rokku","lock93","vxlock","pubg","crab" });

    string stringpath;

    try {
        for (auto const& file : recursive_directory_iterator(cur_dir, fs::directory_options::skip_permission_denied))
        {
            string stringpath = file.path().generic_string();
            string s = stringpath.substr(stringpath.find(".") + 1);
            auto pos = list.find(s);
            auto a = stringpath.c_str();

            wchar_t* wString = new wchar_t[4096];
            MultiByteToWideChar(CP_ACP, 0, a, -1, wString, 4096);

            //LPCWSTR lp = (LPCWSTR)a;

            if (pos != list.end())
            {
                MessageBoxW(NULL, wString, L"High possibility of ransomware!", MB_OK | MB_ICONINFORMATION);
                //cout << "High possibility of ransomware!" << " " << stringpath << "\n";
            }
            else {
                continue;
            }
        }
    }
    catch (const std::filesystem::filesystem_error& ex)
    {
        std::cout << "Exception: " << ex.what() << '\n';
    }
}

int main() {

    string path = "C:/";
    search(path);
    return 0;
}
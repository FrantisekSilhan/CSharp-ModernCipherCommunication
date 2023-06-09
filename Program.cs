﻿using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text;
using KomunikacePomociModernichSifer;

/*cRSA rsa = new cRSA();
byte[] publicKey = rsa.PublicKey;
byte[] privateKey = rsa.PrivateKey;
cRSA.printByte(publicKey);
cRSA.printByte(privateKey);*/

byte[] nemujPublicKey = cRSA.HexStringToByteArray("3082010A0282010100DDBEBE9E312324F3E153EBA77E14B9E94F277055F787890093A70B01B81941FEABE35CDDA4A09E5114CF4112DA7253850A45AA61A88D4BAB3FC2CD68355C8CB19D2380E6C46E0699E4157063FBB753F63156FD6257BCF32E64BC10F9FF33CD4854EC5510EA06CB5250643A6B379658D4F663C23E5E5F408473C0BAB4FB9B41EF96B9B5D8EB567A563E777496B93D857DF52C1109E8B3B5112EED68D846997F638343B516F0BD1C6EA0C63FB78274DD30FA8143F07B0E9DD96FE37E9FF03CD50F4C05F8618D58FC1F2CF821F1864A61417679AF111CA8C4F0C692FC2E7BD996E99A8A8A840768035551FBD35857168ADED390DFA2C0A1B5C344BCC46EB1F120390203010001");
byte[] savedPrivateKey = cRSA.HexStringToByteArray("308204A20201000282010100AF3CE72EE70D0AE19E67B4BA9657A8EFB30D14632029A6594968D3F10E2841A255EAE4CB6B00F77B9AE51D9E8D60524B2C81B903E4D67317CB75CF85CC3E8D8E23AFE7513368E131324812E8EB132327C55CBC9D85B16AF198B2AF605640D3A8B84A21E8D99752A969A236A1A9124D900AD5647DF524A97D2AC105B5CB319491F1A59E927C06CBF209C91CFD800EAA5782817D6563F0AB057440EE4A0A0A2412F0CEFFE22A8CB6D5175C6494E6EB2CE5F24819B27221B59E38BA96F5ADE3611FF2111F8C7B2373ADCC4D38E4DE26DB0E194346515FE589653FD8D52A87B74EC2B4C07443EC8FEBCCDA4A4A3B069D1A17B2869F047FB0A9D6433E402D6000CBF90203010001028201003348447382645BB9D92C8A444C790CD450F6D3EF8A5B05F67D383346091998D3940730BBA2EDDE7F0ABE6023A545F9EF4BF00E9FE819260761A07181BB5AD6FC30CF6A8765DF1C7FD432296E8654CC65F829027DAAC15805A9E528D3AD8A3D26D3FFC5DAA9CAD2030809D3A90D9C709C65BF3B306D4C34598FE87AEE4FAF8BC58A13DD4D7C39753109AEB2EF0B666AEF53EBF3EF83D4FE603F6A9A666935C0FDA0C17639794AA7CEE9C5B04C2F0E698F499DA67CC876707B409F63565531A45D3A6102E5A0CF3E6FF53DB039CF21E2CD896B6D3301C1AF06896301ECFC23232C54D75648DD93A187F673ADB315B330614D9E6ACC62933205D32C7D7DB5E8D07D02818100D5D785B8E161756A65EC8AE57B272E1E7538CC7F8930C338DF383D5DC3D83F2EF046DDA0107972C80556EE7B0BE0938A1D9CA38C6F1017AFBF1DBEFBD2CF661801F2D7A76826B49B72ED01D0C5C52591FAEB4F1035E323769D361C84A0CC95140E1D2E47AC45AC84D86E15146C1EA6B276A7DE3F439B5C678509A9522773CFB702818100D1C90F509EDD53B85C99BAB70ABE952C6D39A2EDFFF4F5F1DA3476200782C43C8AD418E01F0323E3675C27BCAB42DD9FC18B02E58AC9A1DC259E722964DE7CEBE5BAFB5CD288261D720F966047CC2FADF4ECEBA63FA31C356689358EE0413067E4B25E4335E97C912AE2178FC43AB2121DC636C4D0E0D2E28C0A29223694E1CF0281805CA40A2296418A8495B36C590E8962C97F2F2428FC5E4BB50FBF65968189E5958832AB40F4E2287FCF1062309C6CA67E6765BCD4D228BE9A3CC9BE3B8A909F423755E567790F8B9EECA310EE493FA78F1E8D62AB3B2D33E7E723D22703229E5319EA3A6A828F8CB5E0AD902450D2D694EA22BF7DD8E42D9C0B5EAC24134370F10281804E94252C6995359AC4F4C03F77C2D35584C4260747EC958335DC98B27E9DB8AB84C4D55C7DC14B5C0E87324B354B2280889A6D4755A918FBC10B8C6F7CDCE9A5E2B31B1C35AFD1B70DD650D9578B6000A4D169A3280B0CB1E3EA59295F4E8BB71EAEC12823B585774ABCCD5E887E03DD4D51C58A0B436B3A788205CE4EEB8D7902818039FF75661904447E043404F776E0E759294726545E1242D3B40234C89C13677450D3B037F96F7F6124B64890D0FE3A432440A1C01CD0056253423AFCBEFAC0BC5FBCA661242826EC7D9216E495A3EDDCC29F0A41580C608063669E15DC85E6C90E1A3AA5243F378D9E8A22A6FB046D1DA0D4813C5E0B78090B53BBEA1E147E5D");
byte[] encryptedAESKey = cRSA.Encrypt(nemujPublicKey, "E1DA566C0683CDE70DD0D133F752E7F4B3822B7C70F325B091D174D792B2690D");
byte[] encryptedAESIV = cRSA.Encrypt(nemujPublicKey, "61E41F34C4DF5199D8B973869A9C725E");
//cRSA.printByte(encryptedAESKey);
//cRSA.printByte(encryptedAESIV);

byte[] savedEncryptedAESKey = cRSA.HexStringToByteArray("27B4760EBCFF9B03FFAF0E36767EF2D1BCF3B507F1714601D7C5AF8A7342D679E811DF6A4249AEEE4AF5A5B8237B1400BA429CB2F8C15EFD7858F153ACA6FF4294507B60DFB2292ABD5E2A2FDFCDB27EBBF726C6203B9A7F535F06172895A069CF9F72885DEC2B5BF643AB629D3B936F8281D302C95C0D66BDFC85337CEF2A6FFEB834C6C0C4846512F0B455F93CA44D16BE036E1E7BEDC01BE9B95C29BCBB75ACCBC5FBAE0324761A72FB16ECAF45549FAACA111FB243391694C4FCA95E42B45321E619F0E9ADF7DC6B4955A813240A13D4C8E65E29B3ED123B65C9E6A4083F8B88C257E79DBD920FF8D0FA1231D297C474C26F8C2C99A9F3C4DE75DB957830");
byte[] savedEncryptedIVKey = cRSA.HexStringToByteArray("46E2CC0FFBD49C0E0D568DCB46153DDADB74C3058581E2DF2AF89F01F2F5502E45387BC7F577C317CBCA17F24CC78E6344643F125AD49A64F2F81D306B56BB5B5AFAF8FFBBCAE2095B89A3412E29F0C8FE2B64DCAE111A4FF65859B7F98F62E757CF9FBB53706E82EE94F4220E62C645791DF44756B99425B331CC57FDA6C089A3C12CB31FB8CFD26881CCAE55E8E89C165A1D5FBF90C22A57FE59316C8B31BAF77656B72E40352B9FCF13063DA80E722337FE78C3B1B84C92B24D086CB5B87FBF2C79C5381CAFD6560668B060D8C43D027B85740BFB50F139CA37DB0DA27B2219F20D2C1CE3426B0DF1D08D34B201EFD84F4F2DDEA1E445282334BB658375FC");
string savedDecryptedAESKey = cRSA.Decrypt(savedPrivateKey, savedEncryptedAESKey);
string savedDecryptedIVKey = cRSA.Decrypt(savedPrivateKey, savedEncryptedIVKey);
//Console.WriteLine(savedDecryptedAESKey);
//Console.WriteLine(savedDecryptedIVKey);

//Adam
//cAES aes = new cAES();
string message = "Ahoj svete!";
byte[] savedKey = cAES.HexStringToByteArray("E1DA566C0683CDE70DD0D133F752E7F4B3822B7C70F325B091D174D792B2690D");
byte[] savedIv = cAES.HexStringToByteArray("61E41F34C4DF5199D8B973869A9C725E");
byte[] encryptedMessage = cAES.Encrypt(savedKey, savedIv, message);
//cAES.printByte(encryptedMessage);

//Radek
//cAES cAES = new cAES();
byte[] encryptedMessage2 = cAES.HexStringToByteArray("C71CAB52F54FAA98F8C73BAE83DDC464");
byte[] savedKey2 = cAES.HexStringToByteArray("E1DA566C0683CDE70DD0D133F752E7F4B3822B7C70F325B091D174D792B2690D");
byte[] savedIv2 = cAES.HexStringToByteArray("61E41F34C4DF5199D8B973869A9C725E");
string decryptedMessage2 = cAES.Decrypt(savedKey2, savedIv2, encryptedMessage2);

//Console.WriteLine(decryptedMessage2);


/*byte[] key = cAES.Key;
byte[] iv = cAES.Iv;a

foreach (var c in key)
{
    Console.Write(String.Format("{0:X2}", c));
}
Console.WriteLine();
foreach (var c in iv)
{
    Console.Write(String.Format("{0:X2}", c));
}*/

/*foreach (var c in encryptedMessage)
{
    Console.Write(string.Format("{0:X2}", c));
}
Console.WriteLine();*/

//byte[] encryptedMessage = cAES.HexStringToByteArray("3AE769CECEC476C6A9A1BAAB61F210D2");
/*foreach (var c in encryptedMessage)
{
    Console.Write(string.Format("{0:X2}", c));
}*/

/*byte[] received;
using (Aes aesAlg = Aes.Create())
{
    aesAlg.Key = savedKey;
    aesAlg.IV = savedIv;
    ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
    using (MemoryStream msDecrypt = new MemoryStream(encryptedMessage))
    {
        using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
        {
            using (BinaryReader srDecrypt = new BinaryReader(csDecrypt))
            {
                received = srDecrypt.ReadBytes((int)msDecrypt.Length);
            }
        }
    }
}

foreach (var x in received)
{
    Console.Write(String.Format("{0:x2} ", x));
}*/

message = "Ahoj, svete";
//string dostanuHash = "DAB21B8DF1C1C85B57DB5F7083D6711B62CC9FE06250FB3BC0C4D3AB4C124868";
string hash = SHA.GenerateHash(message);
//SHA.PrintMessage(message);

//Console.WriteLine(SHA.VerifyHash(message, dostanuHash));

byte[] encryptedUsingPrivateKey = cRSA.Sign(hash, savedPrivateKey);
//cRSA.printByte(encryptedUsingPrivateKey);



string dostanuMesage = message = "Ahoj, svete";
string dostanuZpravuHash = SHA.GenerateHash(dostanuMesage);
string dostanuEncryptedUsingPrivateKey = "897681AB7E8A18EA9017E7BB35036524FCAFEEE1CE8F520B8332215DFB100E518A85507DD95662C10E14BDF13AFBD48827AC81C4631C5C408B6FFCD41A9D4094FA3ED9130C246E225CB79743EE32ACFCC80EDB39A02355F99867DE52026F2B54A31EDB773D0B76635053875F2F8397D258FE76D1594843A08868B0F0AEED9A7D822A0192350A95F0BC9C2CC0747EF6E62921DB9FD46841786451BE31DDDB01725DF66E58B3D4C5752B365BEC1C7A8A89423475354592FCED7685D2E03F0D0AD7614A82E2EAACA0DACAD088BDD283CDAE6E8F76D801DE4E7252BB13E422609A1E22227EF063AECF148D695DE512490B847A39DCFEDFF338AD1AC3D5026B48A7C2";
string dostanuNemujPublicKey = "3082010A0282010100AF3CE72EE70D0AE19E67B4BA9657A8EFB30D14632029A6594968D3F10E2841A255EAE4CB6B00F77B9AE51D9E8D60524B2C81B903E4D67317CB75CF85CC3E8D8E23AFE7513368E131324812E8EB132327C55CBC9D85B16AF198B2AF605640D3A8B84A21E8D99752A969A236A1A9124D900AD5647DF524A97D2AC105B5CB319491F1A59E927C06CBF209C91CFD800EAA5782817D6563F0AB057440EE4A0A0A2412F0CEFFE22A8CB6D5175C6494E6EB2CE5F24819B27221B59E38BA96F5ADE3611FF2111F8C7B2373ADCC4D38E4DE26DB0E194346515FE589653FD8D52A87B74EC2B4C07443EC8FEBCCDA4A4A3B069D1A17B2869F047FB0A9D6433E402D6000CBF90203010001";

bool messageIsTheSame = cRSA.VerifySignature(dostanuZpravuHash, cRSA.HexStringToByteArray(dostanuEncryptedUsingPrivateKey), dostanuNemujPublicKey);

Console.WriteLine(messageIsTheSame);
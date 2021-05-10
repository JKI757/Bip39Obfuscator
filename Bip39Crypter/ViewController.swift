//
//  ViewController.swift
//  Bip39Crypter
//
//  Created by Joshua Impson on 4/2/21.
//

import Cocoa
import Sodium
import TinyHashes
import BIP39

class ViewController: NSViewController {

    @IBOutlet weak var encryptButton:NSButton?
    @IBOutlet weak var generateButton: NSButton!
    @IBOutlet weak var clearButton: NSButton!
    @IBOutlet weak var bip3924WordField: NSTextField!
    @IBOutlet weak var outtputBip3924WordField: NSTextField!
    @IBOutlet weak var keyField: NSTextField!
    @IBOutlet weak var outputCzechBip39Field: NSTextField!
    @IBOutlet weak var inputCzechBip39Field: NSTextField!

    @IBOutlet weak var debugOutputField: NSTextField!

    let sodium = Sodium();
    let mnemonic =  Mnemonic(strength: 256, wordlist: Wordlists.english);


    override func viewDidLoad() {
        super.viewDidLoad()

        // Do any additional setup after loading the view.
    }



    @IBAction func encryptButtonClicked(_ sender: Any) {

        (outtputBip3924WordField.stringValue,outputCzechBip39Field.stringValue)  = encrypt(inputWords: bip3924WordField.stringValue, key: keyField.stringValue);

    }

    @IBAction func generateButtonClicked(_ sender: Any) {

        keyField.stringValue = (String(bytes: (1...32).map( {_ in UInt8.random(in: 33...126)} ),encoding: .ascii) ?? "").trimmingCharacters(in: .whitespaces);

        bip3924WordField.stringValue = mnemonic.phrase.joined(separator: " ");
        //mnemonic.phrase returns a randomly generated array of 24 words -- this is generated in the constructor call above.

    }


    @IBAction func clearButtonClicked(_ sender: Any) {

        keyField.stringValue = "";
        bip3924WordField.stringValue = "";
        outtputBip3924WordField.stringValue = "";
        outputCzechBip39Field.stringValue = "";
    }

    func stripKey(key:[UInt8]) -> [UInt8]{
        //this function strips off the top bit of each 3d byte --
        //the largest value supported is 2048 so & 0x07FF operation is
        // required on the key so as not to introduce bad data in the upper byte

        var strippedKey: [UInt8]=[];

        for (index, element) in key.enumerated(){
            if (index % 2 == 0){
                strippedKey.append(element & 0x07);//chop off the top 5 bits to
                                                   //match the input data
            }else{
                strippedKey.append(element);
            }
        }
        return strippedKey;
    }

    func keySanitize(key:String)->String{

        //test for bad characters, test for length (must be 32 bits exactly)
        //expand or truncate if necessary


        return key;
    }

    enum keyError: Error {
        case keyTooShort
    }

    func keyExpand(key:String) throws ->[UInt8]{
        let sanitizedKey = keySanitize(key: key);
        let defaultSubKey: [UInt8] = [UInt8(0x00)];
        let subKey1 = sodium.keyDerivation.derive(secretKey: sanitizedKey.bytes, index: 0, length: 32 ,context: "Context!") ?? defaultSubKey;
        let subKey2 = sodium.keyDerivation.derive(secretKey: sanitizedKey.bytes, index: 1, length: 32 ,context: "Context!") ?? defaultSubKey;

        if (subKey1.count == 1 || subKey2.count == 1){
            throw keyError.keyTooShort;
        }

        //  The '!' kills the program if this function returns nil
        let keyBytes1 = stripKey(key:subKey1);
        let keyBytes2 = stripKey(key:subKey2);
        let keyBytes = keyBytes1 + keyBytes2;

        return keyBytes;
    }

//    func getChecksumWordFromPhrase(_ phrase: [String], wordlist: [String] = Wordlists.english) throws -> String {
//        let bits = phrase.map { (word) -> String in
//            let index = wordlist.firstIndex(of: word)!
//            var str = String(index, radix:2)
//            while str.count < 11 {
//                str = "0" + str
//            }
//            return str
//        }.joined(separator: "")
//
//        let dividerIndex = Int(Double(bits.count / 33).rounded(.down) * 32)
//        let entropyBits = String(bits.prefix(dividerIndex))
//
//        let regex = try! NSRegularExpression(pattern: "[01]{1,8}", options: .caseInsensitive)
//        let entropyBytes = regex.matches(in: entropyBits, options: [], range: NSRange(location: 0, length: entropyBits.count)).map {
//            UInt8(strtoul(String(entropyBits[Range($0.range, in: entropyBits)!]), nil, 2))
//        }
//        let checksum = Mnemonic.deriveChecksumBits(entropyBytes);
//        //TODO: figure out exactly what is coming back from derivechecksum bits,
//        //then we need to convert that to bytes and then from there to a valid bip39 word
//        let l = Int(strtoul(checksum, nil, 2));
//        return wordlist[l];
//    }


    func encrypt(inputWords: String, key: String ) -> (String, String) {
        var retString = "";
        var czechRetString = "";
        let strippedInputWords = inputWords.trimmingCharacters(in: [" "]);
        let inputWordsArray = strippedInputWords.components(separatedBy: " ");
        var outputWordIndicesArray:[UInt8] = [];
        var englishWordArray : [String] = [];
        var czechWordArray : [String] = [];

        for word in inputWordsArray{

            if let index:Int = Wordlists.english.firstIndex(of: word){

                let lowerByte = index & 0xFF;
                let highByte = (index>>8) & 0x07;
                outputWordIndicesArray.append(UInt8(highByte));
                outputWordIndicesArray.append(UInt8(lowerByte));
                //we have to split the index value here as the maximum index is 2048
                //Note the & 0x07 to strip the upper bits.  We do the same
                //in key generation.
            }else if let index:Int = Wordlists.czech.firstIndex(of: word){
                let lowerByte = index & 0xFF;
                let highByte = (index>>8) & 0x07;
                outputWordIndicesArray.append(UInt8(highByte));
                outputWordIndicesArray.append(UInt8(lowerByte));
            }else{
                //essentially we have to crash here because we have an invalid word in the input
            }
        }//this only gives us 48 bytes, we need to expand to 64 bytes here, add another 16 bytes of padding.
        do {
            let keyBytes = try keyExpand(key: key);
            let result = outputWordIndicesArray.enumerated().map {$0.element ^ keyBytes[$0.offset]}
            //xor the words and the key

            // put the bytes back together here.  gaagh:
            var encryptedIndices:[UInt16] = [];
            var temp:UInt16 = 0;
            for (index, element) in result.enumerated(){
                if (index % 2 == 0){
                    temp = UInt16(element)<<8;
                }else{
                    temp = temp | ( UInt16(element));
                    encryptedIndices.append(temp);
                    temp = 0;
                }

            }

            for word in encryptedIndices{
                englishWordArray.append(Wordlists.english[Int(word)]);
                czechWordArray.append(Wordlists.czech[Int(word)])
            }

            do {
                englishWordArray[englishWordArray.count-1] = try Mnemonic.getChecksumWordFromPhrase(englishWordArray);
                czechWordArray[czechWordArray.count-1] = try Mnemonic.getChecksumWordFromPhrase(czechWordArray, wordlist: Wordlists.czech);
            }catch{

            }

            for word in encryptedIndices{
                retString += Wordlists.english[Int(word)];
                czechRetString += Wordlists.czech[Int(word)];
                retString += " ";
                czechRetString += " " ;
            }

        }catch {retString = "key Error -- likely Key is too short or unable to be used for some reason"}

        return (retString, czechRetString);
    }


    override var representedObject: Any? {
        didSet {
        // Update the view, if already loaded.
        }
    }


}

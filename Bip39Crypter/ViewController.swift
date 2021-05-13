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

    @IBOutlet weak var LanguageSelectorPopUpButton: NSPopUpButton!

    let sodium = Sodium();
    let mnemonic =  Mnemonic(strength: 256, wordlist: Wordlists.english);


    override func viewDidLoad() {
        super.viewDidLoad()
        
        LanguageSelectorPopUpButton.addItems(withTitles: ["English", "Chinese", "Czech", "Japanese", "Korean", "Spanish", "French", "Italian", "Portuguese"]);

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

    func encrypt(inputWords: String, key: String ) -> (String, String) {
        var retString = "";
        var secondaryRetString = "";
        let strippedInputWords = inputWords.trimmingCharacters(in: [" "]);
        let inputWordsArray = strippedInputWords.components(separatedBy: " ");
        var outputWordIndicesArray:[UInt8] = [];
        var englishWordArray : [String] = [];
        var czechWordArray : [String] = [];

        var secondaryWordArray : [String] = [];


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
            }else if let index:Int = Wordlists.chinese.firstIndex(of: word){
                let lowerByte = index & 0xFF;
                let highByte = (index>>8) & 0x07;
                outputWordIndicesArray.append(UInt8(highByte));
                outputWordIndicesArray.append(UInt8(lowerByte));
            }else if let index:Int = Wordlists.japanese.firstIndex(of: word){
                let lowerByte = index & 0xFF;
                let highByte = (index>>8) & 0x07;
                outputWordIndicesArray.append(UInt8(highByte));
                outputWordIndicesArray.append(UInt8(lowerByte));
            }else if let index:Int = Wordlists.korean.firstIndex(of: word){
                let lowerByte = index & 0xFF;
                let highByte = (index>>8) & 0x07;
                outputWordIndicesArray.append(UInt8(highByte));
                outputWordIndicesArray.append(UInt8(lowerByte));
            }else if let index:Int = Wordlists.spanish.firstIndex(of: word){
                let lowerByte = index & 0xFF;
                let highByte = (index>>8) & 0x07;
                outputWordIndicesArray.append(UInt8(highByte));
                outputWordIndicesArray.append(UInt8(lowerByte));
            }else if let index:Int = Wordlists.french.firstIndex(of: word){
                let lowerByte = index & 0xFF;
                let highByte = (index>>8) & 0x07;
                outputWordIndicesArray.append(UInt8(highByte));
                outputWordIndicesArray.append(UInt8(lowerByte));
            }else if let index:Int = Wordlists.italian.firstIndex(of: word){
                let lowerByte = index & 0xFF;
                let highByte = (index>>8) & 0x07;
                outputWordIndicesArray.append(UInt8(highByte));
                outputWordIndicesArray.append(UInt8(lowerByte));
            }else if let index:Int = Wordlists.portuguese.firstIndex(of: word){
                let lowerByte = index & 0xFF;
                let highByte = (index>>8) & 0x07;
                outputWordIndicesArray.append(UInt8(highByte));
                outputWordIndicesArray.append(UInt8(lowerByte));
            }else{
            //crash because we can't find the word in any dictionary.
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
                switch(LanguageSelectorPopUpButton.indexOfSelectedItem){
                    case 0: secondaryWordArray.append(Wordlists.english[Int(word)]);
                    case 1:secondaryWordArray.append(Wordlists.chinese[Int(word)]);
                    case 2:secondaryWordArray.append(Wordlists.czech[Int(word)]);
                    case 3:secondaryWordArray.append(Wordlists.japanese[Int(word)]);
                    case 4:secondaryWordArray.append(Wordlists.korean[Int(word)]);
                    case 5:secondaryWordArray.append(Wordlists.spanish[Int(word)]);
                    case 6:secondaryWordArray.append(Wordlists.french[Int(word)]);
                    case 7:secondaryWordArray.append(Wordlists.italian[Int(word)]);
                    case 8:secondaryWordArray.append(Wordlists.portuguese[Int(word)]);
                    default: let _ = 0&0;
                }
            }

            do {
                englishWordArray[englishWordArray.count-1] = try Mnemonic.getChecksumWordFromPhrase(englishWordArray);


                switch(LanguageSelectorPopUpButton.indexOfSelectedItem){
                    case 0:secondaryWordArray[secondaryWordArray.count-1] = try Mnemonic.getChecksumWordFromPhrase(secondaryWordArray, wordlist: Wordlists.english);
                    case 1:secondaryWordArray[secondaryWordArray.count-1] = try Mnemonic.getChecksumWordFromPhrase(secondaryWordArray, wordlist: Wordlists.chinese);
                    case 2:secondaryWordArray[secondaryWordArray.count-1] = try Mnemonic.getChecksumWordFromPhrase(secondaryWordArray, wordlist: Wordlists.czech);
                    case 3:secondaryWordArray[secondaryWordArray.count-1] = try Mnemonic.getChecksumWordFromPhrase(secondaryWordArray, wordlist: Wordlists.japanese);
                    case 4:secondaryWordArray[secondaryWordArray.count-1] = try Mnemonic.getChecksumWordFromPhrase(secondaryWordArray, wordlist: Wordlists.korean);
                    case 5:secondaryWordArray[secondaryWordArray.count-1] = try Mnemonic.getChecksumWordFromPhrase(secondaryWordArray, wordlist: Wordlists.spanish);
                    case 6:secondaryWordArray[secondaryWordArray.count-1] = try Mnemonic.getChecksumWordFromPhrase(secondaryWordArray, wordlist: Wordlists.french);
                    case 7:secondaryWordArray[secondaryWordArray.count-1] = try Mnemonic.getChecksumWordFromPhrase(secondaryWordArray, wordlist: Wordlists.italian);
                    case 8:secondaryWordArray[secondaryWordArray.count-1] = try Mnemonic.getChecksumWordFromPhrase(secondaryWordArray, wordlist: Wordlists.portuguese);
                    default: let _ = 0&0;
                }



            }catch{

            }

            for word in encryptedIndices{
                retString += Wordlists.english[Int(word)];
                switch(LanguageSelectorPopUpButton.indexOfSelectedItem){
                    case 0: secondaryRetString += Wordlists.english[Int(word)];
                    case 1:secondaryRetString += Wordlists.chinese[Int(word)];
                    case 2:secondaryRetString += Wordlists.czech[Int(word)];
                    case 3:secondaryRetString += Wordlists.japanese[Int(word)];
                    case 4:secondaryRetString += Wordlists.korean[Int(word)];
                    case 5:secondaryRetString += Wordlists.spanish[Int(word)];
                    case 6:secondaryRetString += Wordlists.french[Int(word)];
                    case 7:secondaryRetString += Wordlists.italian[Int(word)];
                    case 8:secondaryRetString += Wordlists.portuguese[Int(word)];
                    default: let _ = 0&0;
                }
                retString += " ";
                secondaryRetString += " " ;
            }

        }catch {retString = "key Error -- likely Key is too short or unable to be used for some reason"}

        return (retString, secondaryRetString);
    }


    override var representedObject: Any? {
        didSet {
        // Update the view, if already loaded.
        }
    }


}

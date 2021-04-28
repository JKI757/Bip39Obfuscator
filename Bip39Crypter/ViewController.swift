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

    func computeChecksum(key:[UInt16]) -> UInt16{

        let string = "The quick brown fox jumps over the lazy dog"
        let data = string.data(using: .ascii)!;
        let hexDigest = data.sha256;

        var accum:UInt16 = 1;
        for num in key{
            accum *= num;
        }
        accum = accum/256;


//        h=hashlib.sha256(binascii.unhexlify('%064x' % accum)).digest().encode('hex')
//        int(('%064x' % accum)[-1] + h[:2], 16) % 2048


        return 0;
    }
    func encrypt(inputWords: String, key: String ) -> (String, String) {
        var retString = "";
        var czechRetString = "";
        var strippedInputWords = inputWords.trimmingCharacters(in: [" "]);
        let inputWordsArray = strippedInputWords.components(separatedBy: " ");
        var outputWordsArray:[UInt8] = [];


        for word in inputWordsArray{

            if let index:Int = Wordlists.english.firstIndex(of: word){

                let lowerByte = index & 0xFF;
                let highByte = (index>>8) & 0x07;
                outputWordsArray.append(UInt8(highByte));
                outputWordsArray.append(UInt8(lowerByte));
                //we have to split the index value here as the maximum index is 2048
                //Note the & 0x07 to strip the upper bits.  We do the same
                //in key generation.
            }else if let index:Int = Wordlists.czech.firstIndex(of: word){
                let lowerByte = index & 0xFF;
                let highByte = (index>>8) & 0x07;
                outputWordsArray.append(UInt8(highByte));
                outputWordsArray.append(UInt8(lowerByte));
            }else{
                //essentially we have to crash here because we have an invalid word in the input
            }
        }//this only gives us 48 bytes, we need to expand to 64 bytes here, add another 16 bytes of padding.
        do {
            let keyBytes = try keyExpand(key: key);
            let result = outputWordsArray.enumerated().map {$0.element ^ keyBytes[$0.offset]}
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
                retString += Wordlists.english[Int(word)];
                czechRetString += Wordlists.czech[Int(word)];
                retString += " ";
                czechRetString += " " ;
            }
        }catch {
            retString = "key Error -- likely Key is too short or unable to be used for some reason"

        }
        return (retString, czechRetString);
    }


    override var representedObject: Any? {
        didSet {
        // Update the view, if already loaded.
        }
    }


}

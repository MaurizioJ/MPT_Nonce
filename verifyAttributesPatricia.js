import process from 'process';
import { createRequire } from 'module';
import {createPatriciaMerkleTree,CryptoSHAValue} from './createPatriciaMerkleTree.js'
import { SecureTrie as Trie } from 'merkle-patricia-tree'// We import the library required to create a Secure Merkle Patricia Tree
const require = createRequire(import.meta.url);
const util = require('util');
const SHA256 = require('crypto-js/sha256')
const SHA512 = require('crypto-js/sha512')
const SHA3 = require('crypto-js/sha3')
const { MerkleTree } = require('merkletreejs')


let crypto;
var config =require('../config.json');

crypto = require('crypto');
export const verifyAttributes = async (VCs, VP)  => {
    var listHashedKey =[]
    let listValue= VP.vp.attributes
    const listProof = VP.vp.proof
    
    for(const credential of VCs){
        var credVC = credential.credentialSubject
        var root = credVC["root"] // nodo radice della VC
       
        for(let i=0;i<listProof.length;i++) { // verifica di tutti gli attributi presenti nella VP
            listProof[i].listPathNodes = convertToBufferBase64(listProof[i].listPathNodes) // converte i nodi della proof da string a buffer
            let keyAttr = listProof[i].name
            let tmp = listValue[i].split(":") // ricavo il valore i-esimo corrispondente alla chiave i-esima
            let value = tmp[1]
            let objHashed = await CryptoSHAValue(value, listProof[i].nonceValue) //// applico l'hashing + nonce al valore per verificarla
            /*  console.log("valore HASHATO " + i)
              console.log(objHashed.hashedValue)*/

            try {
                let val = await Trie.verifyProof(Buffer.from(root), Buffer.from(keyAttr), listProof[i].listPathNodes) // verifica del nodo
                if (objHashed.hashedValue == val) {
                    // console.log(Buffer.from(objHashed.hashedValue))
                    // console.log(val)
                    // console.log("Il valore dell'attributo verificato è: " + value)
                } else {
                    console.log("Verifica fallita!")
                }
            } catch (e) {
                console.log("Verifica dell'attributo " + keyAttr + " fallita ")
            }
        }
    }

    return ;
}

//Metodo che converte i nodi della proof da string a buffer
export const convertToBufferBase64= (list) =>{
    let proof = []
    for(let elem of list) {
        proof.push(Buffer.from(elem,'base64'))
    }

    return proof
}
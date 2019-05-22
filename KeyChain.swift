//
//  KeyChain.swift
//  Created by charliehsu on 2019/5/20.

import UIKit
import Security


func printLog(_ item:Any){
    #if DEBUG
    print(item)
    #endif
}


struct KeyChain {


    enum KeyChainError:Error {
        case unexpectPasswordData
        case unhandleError(errMsg:String)
    }

    static let current = KeyChain()

    private init() {}

    func save(key:String, password:String) throws -> Bool {
        guard let data = password.data(using: .utf8) else { throw KeyChainError.unexpectPasswordData }
        var query = KeyChain.query()
        query[String(kSecAttrAccount)] = key
        query[String(kSecValueData)] = data
        let status = SecItemAdd(query as CFDictionary, nil)
        return status == noErr
    }

    func load(key:String) throws -> Data? {
        var query = KeyChain.query()
        query[String(kSecAttrAccount)] = key
        query[String(kSecMatchLimit)] = kSecMatchLimitOne
        query[String(kSecReturnData)] = kCFBooleanTrue

        var dataType: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &dataType)

        if let errMsg = getErrorMessage(status: status) {
            throw KeyChainError.unhandleError(errMsg: errMsg)
        }

        return dataType as? Data
    }


    func delete(key:String) throws -> Bool {
        var query = KeyChain.query()
        query[String(kSecAttrAccount)] = key
        let status = SecItemDelete(query as CFDictionary)

        if let errMsg =  getErrorMessage(status: status) {
            throw KeyChainError.unhandleError(errMsg: errMsg)
        }

        return status == noErr
    }

    func update(key:String, data:Data, newkey:String, newData:Data) throws -> Bool {
        //old
        var query = KeyChain.query()
        query[String(kSecValueData)] = data
        query[String(kSecAttrAccount)] = key

        //new
        var attributes = [String:Any]()
        attributes[String(kSecAttrAccount)] = newkey
        attributes[String(kSecValueData)] = newData

        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary )

        if let errMsg =  getErrorMessage(status: status) {
            throw KeyChainError.unhandleError(errMsg: errMsg)
        }

        return status == noErr
    }

    func clear() throws -> Bool {
        let query = KeyChain.query()
        let status = SecItemDelete(query as CFDictionary)

        if let errMsg =  getErrorMessage(status: status) {
            throw KeyChainError.unhandleError(errMsg: errMsg)
        }
        return status == noErr
    }

    private static func query() -> [String:Any] {
        var query: [String:Any] = [String:Any]()
        query[String(kSecClass)] = kSecClassGenericPassword
        return query
    }

    private func getErrorMessage(status: OSStatus) -> String? {

        if status == noErr {
            return nil
        }else if let message = SecCopyErrorMessageString(status, nil) {
            let msg = String(message)
            printLog(msg)
            return msg
        }else{
            return nil
        }
    }


}


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
        case handleError(errMsg:String)
    }

    static let current = KeyChain()

    private init() {}

    func save(key:String, data:Data) throws {
        var query = KeyChain.query()
        query[String(kSecAttrAccount)] = key
        query[String(kSecValueData)] = data
        let status = SecItemAdd(query as CFDictionary, nil)

        if let error = getErrorMessage(status: status) {
            throw error
        }
    }

    func load(key:String) throws -> Data? {
        var query = KeyChain.query()
        query[String(kSecAttrAccount)] = key
        query[String(kSecMatchLimit)] = kSecMatchLimitOne
        query[String(kSecReturnData)] = kCFBooleanTrue

        var dataType: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &dataType)

        if let error = getErrorMessage(status: status) {
            throw error
        }
        return dataType as? Data
    }


    func delete(key:String) throws {
        var query = KeyChain.query()
        query[String(kSecAttrAccount)] = key
        let status = SecItemDelete(query as CFDictionary)

        if let error =  getErrorMessage(status: status) {
            throw error
        }
    }

    func update(key:String, data:Data, newkey:String, newData:Data) throws {
        //old
        var query = KeyChain.query()
        query[String(kSecValueData)] = data
        query[String(kSecAttrAccount)] = key

        //new
        var attributes = [String:Any]()
        attributes[String(kSecAttrAccount)] = newkey
        attributes[String(kSecValueData)] = newData

        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary )

        if let error =  getErrorMessage(status: status) {
            throw error
        }
    }

    func clear() throws {
        let query = KeyChain.query()
        let status = SecItemDelete(query as CFDictionary)
        if let error =  getErrorMessage(status: status) {
            throw error
        }
    }

    private static func query() -> [String:Any] {
        var query: [String:Any] = [String:Any]()
        query[String(kSecClass)] = kSecClassGenericPassword
        return query
    }

    private func getErrorMessage(status: OSStatus) -> KeyChainError? {

        if status == noErr {
            return nil
        }else if let message = SecCopyErrorMessageString(status, nil) {
            let msg = String(message)
            printLog(msg)
            return .handleError(errMsg:msg)
        }else{
            return nil
        }
    }
}

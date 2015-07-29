/*
 * Copyright (C) 2015 Red Bull Media House GmbH <http://www.redbullmediahouse.com> - all rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.rbmhtechnology.eventuate.log.cassandra

import java.io.{File, FileInputStream, InputStream}
import java.security.{KeyStore, SecureRandom}
import javax.net.ssl.{KeyManagerFactory, SSLContext, TrustManagerFactory}

private [cassandra] object CassandraSslSetup {
  /**
   * creates a new SSLContext
   */
  def constructContext(
    trustStorePath:String,
    trustStorePW:String,
    keyStorePath:String,
    keyStorePW:String):SSLContext = {

    val tmf = loadTrustManagerFactory(trustStorePath, trustStorePW)
    val kmf = loadKeyManagerFactory(keyStorePath, keyStorePW)

    val ctx = SSLContext.getInstance("SSL")   
    
    ctx.init(
      kmf.getKeyManagers, 
      tmf.getTrustManagers, 
      new SecureRandom())
    
    ctx
  }

  def loadKeyStore(
    storePath:String,
    storePassword:String):KeyStore = {
    val ks = KeyStore.getInstance("JKS")
    val f = new File(storePath)
    if(!f.isFile) throw new IllegalArgumentException(s"JKSs path $storePath not found.")
    val is = new FileInputStream(f)

    try {
      ks.load(is, storePassword.toCharArray)
    } finally (is.close())

    ks
  }

  def loadTrustManagerFactory(
    trustStorePath:String,
    trustStorePassword:String):TrustManagerFactory = {
    
    val ts = loadKeyStore(trustStorePath, trustStorePassword)
    val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm)
    tmf.init(ts)
    tmf
  }

  def loadKeyManagerFactory(
    keyStorePath:String,
    keyStorePassword:String):KeyManagerFactory = {
    
    val ks = loadKeyStore(keyStorePath, keyStorePassword)
    val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm)
    kmf.init(ks, keyStorePassword.toCharArray)
    kmf
  }
}

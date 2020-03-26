/*
 * Copyright (c) 2013-2019 Snowplow Analytics Ltd.
 * All rights reserved.
 *
 * This program is licensed to you under the Apache License Version 2.0,
 * and you may not use this file except in compliance with the Apache
 * License Version 2.0.
 * You may obtain a copy of the Apache License Version 2.0 at
 * http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Apache License Version 2.0 is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied.
 *
 * See the Apache License Version 2.0 for the specific language
 * governing permissions and limitations there under.
 */
package com.snowplowanalytics.snowplow.enrich.stream

import java.io.{File, FileInputStream}
import java.net.URI
import java.nio.file.{Files, Paths}
import java.util.UUID
import java.util.concurrent.TimeUnit

import cats.Id
import cats.effect.Clock
import cats.syntax.either._
import com.amazonaws.auth.{
  AWSCredentialsProvider,
  AWSStaticCredentialsProvider,
  BasicAWSCredentials,
  DefaultAWSCredentialsProviderChain,
  EnvironmentVariableCredentialsProvider,
  InstanceProfileCredentialsProvider
}
import com.amazonaws.services.s3.AmazonS3ClientBuilder
import com.amazonaws.services.s3.model.GetObjectRequest
import com.google.auth.oauth2.GoogleCredentials
import com.google.cloud.storage.{BlobId, StorageOptions}
import com.snowplowanalytics.snowplow.enrich.common.enrichments.EnrichmentRegistry
import com.snowplowanalytics.snowplow.enrich.stream.model.{
  AWSCredentials,
  Credentials,
  GCPCredentials,
  NoCredentials
}
import com.snowplowanalytics.snowplow.scalatracker.UUIDProvider

object utils {
  def emitPii(enrichmentRegistry: EnrichmentRegistry[Id]): Boolean =
    enrichmentRegistry.piiPseudonymizer.exists(_.emitIdentificationEvent)

  def validatePii(emitPii: Boolean, streamName: Option[String]): Either[String, Unit] =
    (emitPii, streamName) match {
      case (true, None) => "PII was configured to emit, but no PII stream name was given".asLeft
      case _ => ().asRight
    }

  implicit val clockProvider: Clock[Id] = new Clock[Id] {
    final def realTime(unit: TimeUnit): Id[Long] =
      unit.convert(System.currentTimeMillis(), TimeUnit.MILLISECONDS)
    final def monotonic(unit: TimeUnit): Id[Long] =
      unit.convert(System.nanoTime(), TimeUnit.NANOSECONDS)
  }

  implicit val uuidProvider: UUIDProvider[Id] = new UUIDProvider[Id] {
    override def generateUUID: Id[UUID] = UUID.randomUUID()
  }

  def getAWSCredentialsProvider(creds: Credentials): Either[String, AWSCredentialsProvider] = {
    def isDefault(key: String): Boolean = key == "default"
    def isIam(key: String): Boolean = key == "iam"
    def isEnv(key: String): Boolean = key == "env"

    for {
      provider <- creds match {
        case NoCredentials => "No AWS credentials provided".asLeft
        case _: GCPCredentials => "GCP credentials provided".asLeft
        case AWSCredentials(a, s) if isDefault(a) && isDefault(s) =>
          new DefaultAWSCredentialsProviderChain().asRight
        case AWSCredentials(a, s) if isDefault(a) || isDefault(s) =>
          "accessKey and secretKey must both be set to 'default' or neither".asLeft
        case AWSCredentials(a, s) if isIam(a) && isIam(s) =>
          InstanceProfileCredentialsProvider.getInstance().asRight
        case AWSCredentials(a, s) if isIam(a) && isIam(s) =>
          "accessKey and secretKey must both be set to 'iam' or neither".asLeft
        case AWSCredentials(a, s) if isEnv(a) && isEnv(s) =>
          new EnvironmentVariableCredentialsProvider().asRight
        case AWSCredentials(a, s) if isEnv(a) || isEnv(s) =>
          "accessKey and secretKey must both be set to 'env' or neither".asLeft
        case AWSCredentials(a, s) =>
          new AWSStaticCredentialsProvider(new BasicAWSCredentials(a, s)).asRight
      }
    } yield provider
  }

  /**
   * Create GoogleCredentials based on provided service account credentials file
   * @param creds path to service account file
   * @return Either an error or GoogleCredentials
   */
  def getGoogleCredentials(creds: Credentials): Either[String, GoogleCredentials] = {
    def createIfRegular(isRegular: Boolean, path: String): Either[String, GoogleCredentials] =
      if (isRegular)
        Either
          .catchNonFatal(
            GoogleCredentials
              .fromStream(new FileInputStream(path))
              .createScoped("https://www.googleapis.com/auth/cloud-platform")
          )
          .leftMap(_.getMessage)
      else
        "Provided Google Credentials Path isn't valid".asLeft

    creds match {
      case NoCredentials => "No GCP Credentials provided".asLeft
      case _: AWSCredentials => "AWS credentials provided".asLeft
      case GCPCredentials(credsPath) =>
        for {
          path <- Either.catchNonFatal(Paths.get(credsPath)).leftMap(_.getMessage)
          isRegular <- Either.catchNonFatal(Files.isRegularFile(path)).leftMap(_.getMessage)
          gCreds <- createIfRegular(isRegular, credsPath)
        } yield gCreds
    }
  }

  /**
   * Downloads an object from S3 and returns whether or not it was successful.
   * @param uri The URI to reconstruct into a signed S3 URL
   * @param targetFile The file object to write to
   * @param provider necessary credentials to download from S3
   * @return the download result
   */
  def downloadFromS3(
    provider: AWSCredentialsProvider,
    uri: URI,
    targetFile: File
  ): Either[Throwable, Int] =
    Either.catchNonFatal {
      val s3Client = AmazonS3ClientBuilder.standard().withCredentials(provider).build()
      val bucketName = uri.getHost
      val key = uri.getPath match { // Need to remove leading '/'
        case s if s.length > 0 && s.charAt(0) == '/' => s.substring(1)
        case s => s
      }
      s3Client.getObject(new GetObjectRequest(bucketName, key), targetFile)
      0
    }

  def downloadFromGCS(
    creds: GoogleCredentials,
    uri: URI,
    targetFile: File
  ): Either[Throwable, Int] =
    Either.catchNonFatal {
      val storage = StorageOptions.newBuilder().setCredentials(creds).build().getService
      val bucketName = uri.getHost
      val key = uri.getPath match { // Need to remove leading '/'
        case s if s.length > 0 && s.charAt(0) == '/' => s.substring(1)
        case s => s
      }
      storage.get(BlobId.of(bucketName, key)).downloadTo(targetFile.toPath)
      0
    }
}

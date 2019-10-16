package com.example.biometricauthapp.ui.main

import android.os.AsyncTask
import androidx.lifecycle.ViewModelProviders
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import androidx.fragment.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.biometric.BiometricPrompt
import com.example.biometricauthapp.R
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.spec.ECGenParameterSpec

class MainFragment : Fragment() {

    companion object {
        fun newInstance() = MainFragment()
    }

    private lateinit var viewModel: MainViewModel
    private val TAG = "MainFragment"

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        val root = inflater.inflate(R.layout.main_fragment, container, false)
        val textView: TextView = root.findViewById(R.id.message)
        textView.setOnClickListener {
//            password_auth()
            biometric_auth()
        }
        return root
    }

    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)
        viewModel = ViewModelProviders.of(this).get(MainViewModel::class.java)
    }

    fun biometric_auth() {

        val myKeyStore = KeyStore.getInstance("AndroidKeyStore")
        myKeyStore.load(null)

        val keyGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            "AndroidKeyStore"
        )

        // build MY_BIOMETRIC_KEY
        val keyAlias = "MY_BIOMETRIC_KEY"
        val keyProperties = KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        val builder = KeyGenParameterSpec.Builder(keyAlias, keyProperties)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)


        keyGenerator.run {
            initialize(builder.build())
            generateKeyPair()
        }

        val biometricKeyEntry: KeyStore.Entry = myKeyStore.getEntry(keyAlias, null)
        if (biometricKeyEntry !is KeyStore.PrivateKeyEntry) {
            return
        }

        // create signature object
        val signature = Signature.getInstance("SHA256withECDSA")
        // init signature else "IllegalStateException: Crypto primitive not initialized" is thrown
        signature.initSign(biometricKeyEntry.privateKey)
        val cryptoObject = BiometricPrompt.CryptoObject(signature)

        // create biometric prompt
        // NOTE: using androidx.biometric.BiometricPrompt here
        val prompt = BiometricPrompt(
            this,
            AsyncTask.THREAD_POOL_EXECUTOR,
            object : BiometricPrompt.AuthenticationCallback() {
                // override the required methods...
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    Log.w(TAG, "onAuthenticationError $errorCode $errString")
                }

                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    Log.d(TAG, "onAuthenticationSucceeded" + result.cryptoObject)
                    val sigBytes = signature.run {
                        update("hello biometrics".toByteArray())
                        sign()
                    }
                    Log.d(TAG, "sigStr " + Base64.encodeToString(sigBytes, 0))
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    Log.w(TAG, "onAuthenticationFailed")
                }
            })
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Unlock your device")
            .setSubtitle("Please authenticate to ...")
            // negative button option required for biometric auth
            .setNegativeButtonText("Cancel")
            .build()
        prompt.authenticate(promptInfo, cryptoObject)
    }

    fun password_auth() {

        val myKeyStore = KeyStore.getInstance("AndroidKeyStore")
        myKeyStore.load(null)

        val keyGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            "AndroidKeyStore"
        )

        // build MY_PIN_PASSWORD_PATTERN_KEY
        val keyAlias = "MY_PIN_PASSWORD_PATTERN_KEY"
        val keyProperties = KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        val builder = KeyGenParameterSpec.Builder(keyAlias, keyProperties)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            // this would trigger an UserNotAuthenticatedException: User not authenticated when using the fingerprint
            // .setUserAuthenticationRequired(true)
            .setUserAuthenticationValidityDurationSeconds(10)


        keyGenerator.run {
            initialize(builder.build())
            generateKeyPair()
        }

        val keyEntry: KeyStore.Entry = myKeyStore.getEntry(keyAlias, null)
        if (keyEntry !is KeyStore.PrivateKeyEntry) {
            return
        }

        // create signature object
        val signature = Signature.getInstance("SHA256withECDSA")
        // this would fail with UserNotAuthenticatedException: User not authenticated
        // signature.initSign(keyEntry.privateKey)

        // create biometric prompt
        // NOTE: using androidx.biometric.BiometricPrompt here
        val prompt = BiometricPrompt(
            this,
            AsyncTask.THREAD_POOL_EXECUTOR,
            object : BiometricPrompt.AuthenticationCallback() {
                // override the required methods...
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    Log.w(TAG, "onAuthenticationError $errorCode $errString")
                }

                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    Log.d(TAG, "onAuthenticationSucceeded " + result.cryptoObject)
                    // now it's safe to init the signature using the password key
                    signature.initSign(keyEntry.privateKey)
                    val sigBytes = signature.run {
                        update("hello password/pin/pattern".toByteArray())
                        sign()
                    }
                    Log.d(TAG, "sigStr " + Base64.encodeToString(sigBytes, 0))
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    Log.w(TAG, "onAuthenticationFailed")
                }
            })
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Unlock your device")
            .setDeviceCredentialAllowed(true)
            .build()
        prompt.authenticate(promptInfo)
    }

}

#include "psa/crypto.h"

// Session definition and initialization

// typedef /* imp-def */ psa_session_t;
typedef struct {
    uint32_t id;
    uint32_t property;
} psa_session_t;

// #define PSA_SESSION_INIT /* imp-def */
#define PSA_SESSION_INIT { 0, 0 }

// Session attributes

// Session ID *must* be set before opening the session, and is immutable after.
void psa_session_set_id(psa_session_t * ctx, uint32_t id);

// Priority can be set at any time. The attribute value at the time the session
// is used in a function call determines the priority value for that call.
void psa_session_set_priority(psa_session_t * ctx, uint32_t priority);

// Functions to setup/release a session
//
// It is impdef whether a session object is merely a value type, where
// open and close have no effect; or a resource type, where correct use
// of open and close are essential to use. Portable applications should
// always call these functions if they use the session APIs.

// Open a session before using crypto services
//
// A session object that is not open can only be used in calls to
// psa_session_open(), psa_session_set_id(), psa_session_set_priority(),
// psa_session_set_mode(), and psa_session_close()
psa_status_t psa_session_open(psa_session_t * ctx);
// Close an open session.
// Has no effect if called on a session that is not open.
psa_status_t psa_session_close(psa_session_t * ctx);


// API for asynchronous behaviour

// Status values related to asynchronous computation of the request

// The operation cannot be started due to temporary contention for a resource.
// Retry later.
// In [default] synchronous mode this never occurs, as the implementation blocks
// until the resource can be assigned to this operation.
#define PSA_ERROR_RETRY ((psa_status_t)-164)

// The operation has been started, is running in a background thread/processor,
// and has not yet completed. An update on the outstanding operation status
// is obtained by calling psa_session_get_result().
#define PSA_STATUS_PENDING ((psa_status_t)9)


// In blocking mode, all function calls associated with the session will return
// either when the operation is complete or when the operation has failed.
//
// This is the default mode for a session.
#define PSA_SESSION_MODE_BLOCK (0u)
// In asynchronous mode, any function call associated with the session will
// return early if either of the following occurs:
// *  There is temporary contention for a required resource. The caller is
//    recommended to retry the full request later.
// *  The operation is proceeding asynchronously on another thread or processor.
//    The status is pending, and the caller must periodically check the status
//    for operation completion before requesting another operation on the session.
#define PSA_SESSION_MODE_ASYNC (1u)

// Configure session behaviour
// This can only be called prior to opening the session, and the mode cannot be
// changed once the session is open.
psa_status_t psa_session_set_mode(psa_session_t * ctx, uint32_t async);

// Poll the result status for a current pending function call.
// *  If it returns PSA_STATUS_PENDING, the operation is still in progress. This
//    function must be called again later to check for completion.
// *  If it returns any other value, this is the result status of the previously
//    started function. The session can now be used to call another cryptographic
//    function.
psa_status_t psa_session_get_result(const psa_session_t * ctx);

// TBD: behavior of a session:
// *  If operation attempted while another is still pending
// *  If operation is attempted before previous operation status is retrieved
// *  If session is closed while an operation is still pending


// Sample of duplicated session variants of single-part functions
// and multi-part operation setup functions

// During a multi-part operation setup function, the operation is bound
// to the session provided to the setup function. All subsequent functions
// with the operation object use the same session, until the operation
// terminates (either normally, or by being aborted).

psa_status_t psa_session_import_key(const psa_session_t * ctx,
                                    const psa_key_attributes_t * attributes,
                                    const uint8_t * data,
                                    size_t data_length,
                                    psa_key_id_t * key);
psa_status_t psa_session_destroy_key(const psa_session_t * ctx,
                                     psa_key_id_t key);

psa_status_t psa_session_hash_setup(const psa_session_t * ctx,
                                    psa_hash_operation_t * operation,
                                    psa_algorithm_t alg);

psa_status_t psa_session_verify_hash(const psa_session_t * ctx,
                                     psa_key_id_t key,
                                     psa_algorithm_t alg,
                                     const uint8_t * hash,
                                     size_t hash_length,
                                     const uint8_t * signature,
                                     size_t signature_length);

psa_status_t psa_session_hash_compute(const psa_session_t * ctx,
                                      psa_algorithm_t alg,
                                      const uint8_t * input,
                                      size_t input_length,
                                      uint8_t * hash,
                                      size_t hash_size,
                                      size_t * hash_length);

// Example usage of the additional API

static psa_session_t blocking_ctx = PSA_SESSION_INIT;

void session_setup()
{
    // Initialise library
    psa_crypto_init();

    // Set up session
    psa_session_t ctx = PSA_SESSION_INIT;
    psa_session_set_id(&blocking_ctx, 12345);
    psa_set_session_mode(&blocking_ctx, PSA_SESSION_MODE_BLOCK);
    psa_session_open(&blocking_ctx);
}

void session_close()
{
    psa_session_close(&blocking_ctx);
}

bool session_sign(const uint8_t * key_data, size_t key_length,
                  const uint8_t * msg, size_t msg_length,
                  const uint8_t * sig, size_t sig_length)
{
    // Verifying a signature using a multi-part hash and then signature verification
    // on a previously opened session
    // (No error handling shown)

    // Configure session
    psa_session_set_priority(&blocking_ctx, 100);

    // import public key
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

    psa_key_id_t key;
    psa_session_import_key(&blocking_ctx, &attr, key_data, key_length, &key);

    // compute message hash
    psa_hash_operation_t hash_op = PSA_HASH_OPERATION_INIT;
    psa_session_hash_setup(&blocking_ctx, &hash_op, PSA_ALG_SHA_256);
    // Note: the session is not required in calls after the operation has been set up
    psa_hash_update(&hash_op, msg, msg_length);
    uint8_t hash[PSA_HASH_LENGTH(PSA_ALG_SHA_256)];
    size_t hash_len;
    psa_hash_finish(&hash_op, &hash, sizeof(hash), &hash_len);

    // verify message signature
    psa_status_t result = psa_session_verify_hash(&blocking_ctx,
                                                  key, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                                                  &hash, hash_len,
                                                  sig, sig_length);

    // clean up temporary key
    psa_session_destroy_key(&blocking_ctx, key);

    return result == PSA_SUCCESS;
}


psa_status_t async_demo(const uint8_t * msg, size_t msg_length,
                        uint8_t * hash, size_t hash_size, size_t * hash_length)
{
    // Asynchronously compute a hash

    // Configure session
    // In real applications, the context will be longer-lived and be already initialised.
    psa_session_t async_ctx = PSA_SESSION_INIT;

    psa_session_set_id(&async_ctx, 5);
    psa_set_session_mode(&async_ctx, PSA_SESSION_MODE_ASYNC);
    psa_session_open(&async_ctx);
    psa_session_set_priority(&blocking_ctx, 200);

    // Compute message hash
    //
    // In a real application use of the asynchronous behaviour, the calls to the API
    // will more typically be driven by a state machine, enabling the application
    // thread to carry out other activity while the operation proceeds asynchronously.
    // This example is written procedurally, in order to more easily illustrate the
    // way the new API elements work.

    psa_status_t stat;

    for (;;) {
        stat = psa_session_hash_compute(&async_ctx, PSA_ALG_SHA_256,
                                        msg, msg_length,
                                        hash, hash_size, hash_length);
        if (stat != PSA_ERROR_RETRY)
            break;
        // Yield/back-off before retrying
        yield();
    }
    while (stat == PSA_STATUS_PENDING)
    {
        // do something useful while hash runs in the background
        do_something_while_we_wait();
        // ...
        stat = psa_session_get_result(&async_ctx);
    }

    psa_session_close(&async_ctx);

    return stat;
}

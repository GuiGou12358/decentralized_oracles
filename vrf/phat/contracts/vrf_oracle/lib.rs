#![cfg_attr(not(feature = "std"), no_std, no_main)]

extern crate alloc;
extern crate core;

#[ink::contract(env = pink_extension::PinkEnvironment)]
mod vrf_oracle {
    use alloc::{format, string::String, string::ToString, vec, vec::Vec};
    use ink::storage::Lazy;
    use phat_offchain_rollup::clients::ink::{Action, ContractId, InkRollupClient};
    use pink_extension::chain_extension::signing;
    use pink_extension::{error, info, ResultExt};
    use scale::{Decode, Encode};

    /// Message to request the random value
    /// message pushed in the queue by this contract and read by the offchain rollup
    #[derive(Eq, PartialEq, Clone, scale::Encode, scale::Decode)]
    struct RandomValueRequestMessage {
        /// id of the requestor
        requestor_id: AccountId,
        /// nonce of the requestor
        requestor_nonce: u128,
        /// minimum value requested
        min: u128,
        /// maximum value requested
        max: u128,
    }
    /// Message sent to provide the price of the trading pair
    /// response pushed in the queue by the offchain rollup and read by this contract
    #[derive(Encode, Decode)]
    struct RandomValueResponseMessage {
        /// Type of response
        resp_type: u8,
        /// initial request
        request: RandomValueRequestMessage,
        /// random_value
        random_value: Option<u128>,
        /// when an error occurs
        error: Option<Vec<u8>>,
    }

    /// Type of response when the offchain rollup communicates with this contract
    const TYPE_ERROR: u8 = 0;
    const TYPE_RESPONSE: u8 = 10;

    #[ink(storage)]
    pub struct Vrf {
        owner: AccountId,
        /// config to send the data to the ink! smart contract
        config: Option<Config>,
        /// Key for signing the rollup tx.
        attest_key: [u8; 32],
        /// The JS code that processes the rollup queue request
        core_js: Lazy<CoreJs>,
    }

    type CodeHash = [u8; 32];

    #[derive(Encode, Decode, Debug, Clone)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct CoreJs {
        /// The JS code that processes the rollup queue request
        script: String,
        /// The configuration that would be passed to the core js script
        settings: String,
        /// The code hash of the core js script
        code_hash: CodeHash,
    }

    #[derive(Encode, Decode, Debug)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    struct Config {
        /// The RPC endpoint of the target blockchain
        rpc: String,
        pallet_id: u8,
        call_id: u8,
        /// The rollup anchor address on the target blockchain
        contract_id: ContractId,
        /// Key for sending out the rollup meta-tx. None to fallback to the wallet based auth.
        sender_key: Option<[u8; 32]>,
    }

    #[derive(Encode, Decode, Debug)]
    #[repr(u8)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum ContractError {
        BadOrigin,
        ClientNotConfigured,
        CoreNotConfigured,
        InvalidKeyLength,
        InvalidAddressLength,
        NoRequestInQueue,
        FailedToCreateClient,
        FailedToCommitTx,
        FailedToFetchPrice,

        FailedToGetStorage,
        FailedToCreateTransaction,
        FailedToSendTransaction,
        FailedToGetBlockHash,
        FailedToDecode,
        InvalidRequest,
        FailedToCallRollup,

        MinGreaterThanMax,
        JsError(String),
        ParseIntError(String),
    }

    type Result<T> = core::result::Result<T, ContractError>;

    impl From<phat_offchain_rollup::Error> for ContractError {
        fn from(error: phat_offchain_rollup::Error) -> Self {
            error!("error in the rollup: {:?}", error);
            ContractError::FailedToCallRollup
        }
    }

    impl Vrf {
        #[ink(constructor)]
        pub fn default() -> Self {
            const NONCE: &[u8] = b"attest_key";
            let private_key = signing::derive_sr25519_key(NONCE);
            Self {
                owner: Self::env().caller(),
                attest_key: private_key[..32].try_into().expect("Invalid Key Length"),
                config: None,
                core_js: Default::default(),
            }
        }

        /// Gets the owner of the contract
        #[ink(message)]
        pub fn owner(&self) -> AccountId {
            self.owner
        }

        /// Gets the attestor address used by this rollup
        #[ink(message)]
        pub fn get_attest_address(&self) -> Vec<u8> {
            signing::get_public_key(&self.attest_key, signing::SigType::Sr25519)
        }

        /// Gets the ecdsa address used by this rollup in the meta transaction
        #[ink(message)]
        pub fn get_attest_ecdsa_address(&self) -> Vec<u8> {
            use ink::env::hash;
            let input = signing::get_public_key(&self.attest_key, signing::SigType::Ecdsa);
            let mut output = <hash::Blake2x256 as hash::HashOutput>::Type::default();
            ink::env::hash_bytes::<hash::Blake2x256>(&input, &mut output);
            output.to_vec()
        }

        /// Set attestor key.
        ///
        /// For dev purpose.
        #[ink(message)]
        pub fn set_attest_key(&mut self, attest_key: Option<Vec<u8>>) -> Result<()> {
            self.attest_key = match attest_key {
                Some(key) => key.try_into().or(Err(ContractError::InvalidKeyLength))?,
                None => {
                    const NONCE: &[u8] = b"attest_key";
                    let private_key = signing::derive_sr25519_key(NONCE);
                    private_key[..32]
                        .try_into()
                        .or(Err(ContractError::InvalidKeyLength))?
                }
            };
            Ok(())
        }

        /// Gets the sender address used by this rollup
        #[ink(message)]
        pub fn get_sender_address(&self) -> Option<Vec<u8>> {
            if let Some(Some(sender_key)) = self.config.as_ref().map(|c| c.sender_key.as_ref()) {
                let sender_key = signing::get_public_key(sender_key, signing::SigType::Sr25519);
                Some(sender_key)
            } else {
                None
            }
        }

        /// Gets the config
        #[ink(message)]
        pub fn get_target_contract(&self) -> Option<(String, u8, u8, ContractId)> {
            self.config.as_ref().map(|c| (c.rpc.clone(), c.pallet_id, c.call_id, c.contract_id))
        }

        /// Configures the rollup target (admin only)
        #[ink(message)]
        pub fn config_target_contract(
            &mut self,
            rpc: String,
            pallet_id: u8,
            call_id: u8,
            contract_id: Vec<u8>,
            sender_key: Option<Vec<u8>>,
        ) -> Result<()> {
            self.ensure_owner()?;
            self.config = Some(Config {
                rpc,
                pallet_id,
                call_id,
                contract_id: contract_id
                    .try_into()
                    .or(Err(ContractError::InvalidAddressLength))?,
                sender_key: match sender_key {
                    Some(key) => Some(key.try_into().or(Err(ContractError::InvalidKeyLength))?),
                    None => None,
                },
            });
            Ok(())
        }

        #[ink(message)]
        pub fn get_core_js(&self) -> Option<CoreJs> {
            self.core_js.get()
        }

        /// Configures the core script (admin only)
        #[ink(message)]
        pub fn config_core_js(&mut self, core_js: String, settings: String) -> Result<()> {
            self.ensure_owner()?;
            self.config_core_js_inner(core_js, settings);
            Ok(())
        }

        fn config_core_js_inner(&mut self, core_js: String, settings: String) {
            let code_hash = self
                .env()
                .hash_bytes::<ink::env::hash::Sha2x256>(core_js.as_bytes());
            // TODO: To avoid wasting storage, we can
            // - make a generic contract to store k-v pairs.
            // - use the hash as the key to store the js.
            // - store only hash in the app contract.
            self.core_js.set(&CoreJs {
                script: core_js,
                settings,
                code_hash,
            });
        }

        /// Set the configuration (admin only)
        #[ink(message)]
        pub fn config_core_js_settings(&mut self, settings: String) -> Result<()> {
            self.ensure_owner()?;
            let Some(mut core) = self.core_js.get() else {
                return Err(ContractError::CoreNotConfigured);
            };
            core.settings = settings;
            self.core_js.set(&core);
            Ok(())
        }

        /// Transfers the ownership of the contract (admin only)
        #[ink(message)]
        pub fn transfer_ownership(&mut self, new_owner: AccountId) -> Result<()> {
            self.ensure_owner()?;
            self.owner = new_owner;
            Ok(())
        }

        /// Processes a request by a rollup transaction
        #[ink(message)]
        pub fn answer_request(&self) -> Result<Option<Vec<u8>>> {
            let config = self.ensure_client_configured()?;
            let mut client = connect(config)?;

            // Get a request if presents
            let request: RandomValueRequestMessage = client
                .pop()
                .log_err("answer_request: failed to read queue")?
                .ok_or(ContractError::NoRequestInQueue)?;

            let response = self.handle_request(request)?;
            // Attach an action to the tx by:
            client.action(Action::Reply(response.encode()));

            maybe_submit_tx(client, &self.attest_key, config.sender_key.as_ref())
        }

        fn handle_request(
            &self,
            request: RandomValueRequestMessage,
        ) -> Result<RandomValueResponseMessage> {
            /*
            let Some(Core{ script, settings, code_hash }) = self.core.get() else {
                error!("CoreNotConfigured");
                return Err(ContractError::CoreNotConfigured);
            };
             */
            let requestor_id = request.requestor_id;
            let requestor_nonce = request.requestor_nonce;
            let min = request.min;
            let max = request.max;

            if min > max {
                let response = RandomValueResponseMessage {
                    resp_type: TYPE_ERROR,
                    request,
                    random_value: None,
                    error: Some(ContractError::MinGreaterThanMax.encode()),
                };
                return Ok(response);
            }

            info!(
                "Request received from {requestor_id:?}/{requestor_nonce} - random value between {min} and {max}"
            );

            let response = match self.get_random(min, max) {
                Ok(random_value) => {
                    RandomValueResponseMessage {
                        resp_type: TYPE_RESPONSE,
                        request,
                        random_value: Some(random_value),
                        error: None,
                    }
                }
                Err(e) => {
                    RandomValueResponseMessage {
                        resp_type: TYPE_ERROR,
                        request,
                        random_value: None,
                        error: Some(e.encode()),
                    }
                }
            };
            Ok(response)
            //Ok((output, code_hash))
        }

        #[ink(message)]
        pub fn get_random(&self, min: u128, max: u128) -> Result<u128> {
            let js_code = format!(
                r#"
                    (() => {{
                        let value = Math.floor(Math.random() * ({max} - {min} + 1)) + {min};
                        return value
                    }})();
                "#
            );
            let args = vec![];
            let result = self.get_js_result(js_code, args)?;
            info!("random value between {min} and {max} :  {result:?}");
            let value = result.as_str().parse::<u128>()
                .map_err(|e| ContractError::ParseIntError(e.to_string()))?;
            Ok(value)
        }

        fn get_js_result(&self, js_code: String, args: Vec<String>) -> Result<String> {
            let output = phat_js::eval(&js_code, &args)
                .log_err("Failed to eval the core js")
                .map_err(ContractError::JsError)?;

            let output_as_bytes = match output {
                phat_js::Output::String(s) => s.into_bytes(),
                phat_js::Output::Bytes(b) => b,
                phat_js::Output::Undefined => return Err(ContractError::JsError("Undefined output".to_string())),
            };
            Ok(String::from_utf8(output_as_bytes).unwrap())
        }

        /// Returns BadOrigin error if the caller is not the owner
        fn ensure_owner(&self) -> Result<()> {
            if self.env().caller() == self.owner {
                Ok(())
            } else {
                Err(ContractError::BadOrigin)
            }
        }

        /// Returns the config reference or raise the error `ClientNotConfigured`
        fn ensure_client_configured(&self) -> Result<&Config> {
            self.config
                .as_ref()
                .ok_or(ContractError::ClientNotConfigured)
        }
    }

    fn connect(config: &Config) -> Result<InkRollupClient> {
        let result = InkRollupClient::new(
            &config.rpc,
            config.pallet_id,
            config.call_id,
            &config.contract_id,
        )
        .log_err("failed to create rollup client");

        match result {
            Ok(client) => Ok(client),
            Err(e) => {
                error!("Error : {:?}", e);
                Err(ContractError::FailedToCreateClient)
            }
        }
    }

    fn maybe_submit_tx(
        client: InkRollupClient,
        attest_key: &[u8; 32],
        sender_key: Option<&[u8; 32]>,
    ) -> Result<Option<Vec<u8>>> {
        let maybe_submittable = client
            .commit()
            .log_err("failed to commit")
            .map_err(|_| ContractError::FailedToCommitTx)?;

        if let Some(submittable) = maybe_submittable {
            let tx_id = if let Some(sender_key) = sender_key {
                // Prefer to meta-tx
                submittable
                    .submit_meta_tx(attest_key, sender_key)
                    .log_err("failed to submit rollup meta-tx")?
            } else {
                // Fallback to account-based authentication
                submittable
                    .submit(attest_key)
                    .log_err("failed to submit rollup tx")?
            };
            return Ok(Some(tx_id));
        }
        Ok(None)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ink::env::debug_println;

        struct EnvVars {
            /// The RPC endpoint of the target blockchain
            rpc: String,
            pallet_id: u8,
            call_id: u8,
            /// The rollup anchor address on the target blockchain
            contract_id: ContractId,
            /// When we want to manually set the attestor key for signing the message (only dev purpose)
            attest_key: Vec<u8>,
            /// When we want to use meta tx
            sender_key: Option<Vec<u8>>,
        }

        fn get_env(key: &str) -> String {
            std::env::var(key).expect("env not found")
        }

        fn config() -> EnvVars {
            dotenvy::dotenv().ok();
            let rpc = get_env("RPC");
            let pallet_id: u8 = get_env("PALLET_ID").parse().expect("u8 expected");
            let call_id: u8 = get_env("CALL_ID").parse().expect("u8 expected");
            let contract_id: ContractId = hex::decode(get_env("CONTRACT_ID"))
                .expect("hex decode failed")
                .try_into()
                .expect("incorrect length");
            let attest_key = hex::decode(get_env("ATTEST_KEY")).expect("hex decode failed");
            let sender_key = std::env::var("SENDER_KEY")
                .map(|s| hex::decode(s).expect("hex decode failed"))
                .ok();

            EnvVars {
                rpc: rpc.to_string(),
                pallet_id,
                call_id,
                contract_id: contract_id.into(),
                attest_key,
                sender_key,
            }
        }

        #[ink::test]
        fn test_update_attestor_key() {
            let _ = env_logger::try_init();
            pink_extension_runtime::mock_ext::mock_all_ext();

            let mut vrf = Vrf::default();

            // Secret key and address of Alice in localhost
            let sk_alice: [u8; 32] = [0x01; 32];
            let address_alice = hex_literal::hex!(
                "189dac29296d31814dc8c56cf3d36a0543372bba7538fa322a4aebfebc39e056"
            );

            let initial_attestor_address = vrf.get_attest_address();
            assert_ne!(address_alice, initial_attestor_address.as_slice());

            vrf.set_attest_key(Some(sk_alice.into())).unwrap();

            let attestor_address = vrf.get_attest_address();
            assert_eq!(address_alice, attestor_address.as_slice());

            vrf.set_attest_key(None).unwrap();

            let attestor_address = vrf.get_attest_address();
            assert_eq!(initial_attestor_address, attestor_address);
        }

        fn init_contract() -> Vrf {
            let EnvVars {
                rpc,
                pallet_id,
                call_id,
                contract_id,
                attest_key,
                sender_key,
            } = config();

            let mut vrf = Vrf::default();
            vrf.config_target_contract(rpc, pallet_id, call_id, contract_id.into(), sender_key)
                .unwrap();
            vrf.set_attest_key(Some(attest_key)).unwrap();

            vrf
        }

        #[ink::test]
        fn get_js_result() {
            let _ = env_logger::try_init();
            pink_extension_runtime::mock_ext::mock_all_ext();

            debug_println!("1");

            let vrf = init_contract();

            let a = 5;
            let b = 9;
            let js_code = format!(
                r#"
                    (() => {{
                        let total = {a} + {b};
                        return total
                    }})();
                "#
            );
            let args = vec![];
            let result = vrf.get_js_result(js_code, args).unwrap();
            debug_println!("random number: {result:?}");
        }

        #[ink::test]
        //#[ignore = "the target contract must be deployed in local node or shibuya"]
        fn get_random_number() {
            let _ = env_logger::try_init();
            pink_extension_runtime::mock_ext::mock_all_ext();

            let vrf = init_contract();

            let r = vrf.get_random(10, 100);

            debug_println!("random number: {r:?}");
        }

        #[ink::test]
        #[ignore = "the target contract must be deployed in local node or shibuya"]
        fn answer_price_request() {
            let _ = env_logger::try_init();
            pink_extension_runtime::mock_ext::mock_all_ext();

            let vrf = init_contract();

            let r = vrf.answer_request().expect("failed to answer request");
            debug_println!("answer request: {r:?}");
        }
    }
}

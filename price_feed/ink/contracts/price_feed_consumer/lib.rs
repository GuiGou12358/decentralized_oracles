#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[openbrush::implementation(Ownable, AccessControl)]
#[openbrush::contract]
pub mod price_feed_consumer {
    use ink::codegen::{EmitEvent, Env};
    use ink::prelude::string::String;
    use ink::prelude::vec::Vec;
    use ink::storage::Mapping;
    use openbrush::contracts::access_control::*;
    use openbrush::contracts::ownable::*;
    use openbrush::traits::Storage;
    use scale::{Decode, Encode};

    use phat_rollup_anchor_ink::traits::{
        meta_transaction, meta_transaction::*, rollup_anchor, rollup_anchor::*,
    };

    pub type TradingPairId = u32;

    pub const MANAGER_ROLE: RoleType = ink::selector_id!("MANAGER_ROLE");

    /// Events emitted when a price is received
    #[ink(event)]
    pub struct PriceReceived {
        trading_pair_id: TradingPairId,
        price: u128,
    }

    /// Events emitted when a error is received
    #[ink(event)]
    pub struct ErrorReceived {
        trading_pair_id: TradingPairId,
        err_no: u128,
    }

    /// Errors occurred in the contract
    #[derive(Encode, Decode, Debug)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum ContractError {
        AccessControlError(AccessControlError),
        RollupAnchorError(RollupAnchorError),
        MetaTransactionError(MetaTransactionError),
        MissingTradingPair,
    }
    /// convertor from AccessControlError to ContractError
    impl From<AccessControlError> for ContractError {
        fn from(error: AccessControlError) -> Self {
            ContractError::AccessControlError(error)
        }
    }
    /// convertor from RollupAnchorError to ContractError
    impl From<RollupAnchorError> for ContractError {
        fn from(error: RollupAnchorError) -> Self {
            ContractError::RollupAnchorError(error)
        }
    }
    /// convertor from MetaTxError to ContractError
    impl From<MetaTransactionError> for ContractError {
        fn from(error: MetaTransactionError) -> Self {
            ContractError::MetaTransactionError(error)
        }
    }

    /// Message to request the price of the trading pair
    /// message pushed in the queue by this contract and read by the offchain rollup
    #[derive(Encode, Decode)]
    struct PriceRequestMessage {
        /// id of the pair (use as key in the Mapping)
        trading_pair_id: TradingPairId,
        /// trading pair like 'polkdatot/usd'
        /// Note: it will be better to not save this data in the storage
        token0: String,
        token1: String,
    }
    /// Message sent to provide the price of the trading pair
    /// response pushed in the queue by the offchain rollup and read by this contract
    #[derive(Encode, Decode)]
    struct PriceResponseMessage {
        /// Type of response
        resp_type: u8,
        /// id of the pair
        trading_pair_id: TradingPairId,
        /// price of the trading pair
        price: Option<u128>,
        /// when the price is read
        err_no: Option<u128>,
    }

    /// Type of response when the offchain rollup communicates with this contract
    const TYPE_ERROR: u8 = 0;
    const TYPE_RESPONSE: u8 = 10;
    const TYPE_FEED: u8 = 11;

    /// Data storage
    #[derive(Encode, Decode, Default, Eq, PartialEq, Clone, Debug)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct TradingPair {
        /// trading pair like 'polkdatot/usd'
        /// Note: it will be better to not save this data outside of the storage
        token0: String,
        token1: String,
        /// value of the trading pair
        value: u128,
        /// number of updates of the value
        nb_updates: u16,
        /// when the last value has been updated
        last_update: u64,
    }

    #[ink(storage)]
    #[derive(Default, Storage)]
    pub struct TestOracle {
        #[storage_field]
        ownable: ownable::Data,
        #[storage_field]
        access: access_control::Data,
        #[storage_field]
        rollup_anchor: rollup_anchor::Data,
        #[storage_field]
        meta_transaction: meta_transaction::Data,
        trading_pairs: Mapping<TradingPairId, TradingPair>,
    }

    impl TestOracle {
        #[ink(constructor)]
        pub fn new() -> Self {
            let mut instance = Self::default();
            let caller = instance.env().caller();
            // set the owner of this contract
            ownable::Internal::_init_with_owner(&mut instance, caller);
            // set the admin of this contract
            access_control::Internal::_init_with_admin(&mut instance, Some(caller));
            // grant the role manager
            AccessControl::grant_role(&mut instance, MANAGER_ROLE, Some(caller))
                .expect("Should grant the role MANAGER_ROLE");
            instance
        }

        #[ink(message)]
        #[openbrush::modifiers(access_control::only_role(MANAGER_ROLE))]
        pub fn create_trading_pair(
            &mut self,
            trading_pair_id: TradingPairId,
            token0: String,
            token1: String,
        ) -> Result<(), ContractError> {
            // we create a new trading pair or override an existing one
            let trading_pair = TradingPair {
                token0,
                token1,
                value: 0,
                nb_updates: 0,
                last_update: 0,
            };
            self.trading_pairs.insert(trading_pair_id, &trading_pair);
            Ok(())
        }

        #[ink(message)]
        #[openbrush::modifiers(access_control::only_role(MANAGER_ROLE))]
        pub fn request_price(
            &mut self,
            trading_pair_id: TradingPairId,
        ) -> Result<QueueIndex, ContractError> {
            let index = match self.trading_pairs.get(trading_pair_id) {
                Some(t) => {
                    // push the message in the queue
                    let message = PriceRequestMessage {
                        trading_pair_id,
                        token0: t.token0,
                        token1: t.token1,
                    };
                    self.push_message(&message)?
                }
                _ => return Err(ContractError::MissingTradingPair),
            };

            Ok(index)
        }

        #[ink(message)]
        pub fn get_trading_pair(&self, trading_pair_id: TradingPairId) -> Option<TradingPair> {
            self.trading_pairs.get(trading_pair_id)
        }

        #[ink(message)]
        pub fn register_attestor(&mut self, account_id: AccountId) -> Result<(), ContractError> {
            AccessControl::grant_role(self, ATTESTOR_ROLE, Some(account_id))?;
            Ok(())
        }

        #[ink(message)]
        pub fn get_attestor_role(&self) -> RoleType {
            ATTESTOR_ROLE
        }

        #[ink(message)]
        pub fn get_manager_role(&self) -> RoleType {
            MANAGER_ROLE
        }
    }

    impl RollupAnchor for TestOracle {}
    impl MetaTransaction for TestOracle {}

    impl rollup_anchor::MessageHandler for TestOracle {
        fn on_message_received(&mut self, action: Vec<u8>) -> Result<(), RollupAnchorError> {
            // parse the response
            let message: PriceResponseMessage =
                Decode::decode(&mut &action[..]).or(Err(RollupAnchorError::FailedToDecode))?;

            // handle the response
            if message.resp_type == TYPE_RESPONSE || message.resp_type == TYPE_FEED {
                // we received the price
                // register the info
                let mut trading_pair = self
                    .trading_pairs
                    .get(message.trading_pair_id)
                    .unwrap_or_default();
                trading_pair.value = message.price.unwrap_or_default();
                trading_pair.nb_updates += 1;
                trading_pair.last_update = self.env().block_timestamp();
                self.trading_pairs
                    .insert(message.trading_pair_id, &trading_pair);

                // emmit te event
                self.env().emit_event(PriceReceived {
                    trading_pair_id: message.trading_pair_id,
                    price: message.price.unwrap_or_default(),
                });
            } else if message.resp_type == TYPE_ERROR {
                // we received an error
                self.env().emit_event(ErrorReceived {
                    trading_pair_id: message.trading_pair_id,
                    err_no: message.err_no.unwrap_or_default(),
                });
            } else {
                // response type unknown
                return Err(RollupAnchorError::UnsupportedAction);
            }

            Ok(())
        }
    }

    /// Events emitted when a message is pushed in the queue
    #[ink(event)]
    pub struct MessageQueued {
        pub id: u32,
        pub data: Vec<u8>,
    }

    /// Events emitted when a message is proceed
    #[ink(event)]
    pub struct MessageProcessedTo {
        pub id: u32,
    }

    impl rollup_anchor::EventBroadcaster for TestOracle {
        fn emit_event_message_queued(&self, id: u32, data: Vec<u8>) {
            self.env().emit_event(MessageQueued { id, data });
        }

        fn emit_event_message_processed_to(&self, id: u32) {
            self.env().emit_event(MessageProcessedTo { id });
        }
    }

    impl meta_transaction::EventBroadcaster for TestOracle {
        fn emit_event_meta_tx_decoded(&self) {
            self.env().emit_event(MetaTxDecoded {});
        }
    }

    /// Events emitted when a meta transaction is decoded
    #[ink(event)]
    pub struct MetaTxDecoded {}

    #[cfg(all(test, feature = "e2e-tests"))]
    mod e2e_tests {
        use super::*;
        use ink::env::DefaultEnvironment;
        use openbrush::contracts::access_control::accesscontrol_external::AccessControl;

        use ink_e2e::subxt::tx::Signer;
        use ink_e2e::{build_message, PolkadotConfig};

        use phat_rollup_anchor_ink::traits::{
            meta_transaction::metatransaction_external::MetaTransaction,
            rollup_anchor::rollupanchor_external::RollupAnchor,
        };

        type E2EResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

        async fn alice_instantiates_contract(
            client: &mut ink_e2e::Client<PolkadotConfig, DefaultEnvironment>,
        ) -> AccountId {
            let constructor = TestOracleRef::new();
            client
                .instantiate(
                    "price_feed_consumer",
                    &ink_e2e::alice(),
                    constructor,
                    0,
                    None,
                )
                .await
                .expect("instantiate failed")
                .account_id
        }

        async fn alice_creates_trading_pair(
            client: &mut ink_e2e::Client<PolkadotConfig, DefaultEnvironment>,
            contract_id: &AccountId,
            trading_pair_id: &TradingPairId
        ) {
            // create the trading pair
            let create_trading_pair =
                build_message::<TestOracleRef>(contract_id.clone()).call(|oracle| {
                    oracle.create_trading_pair(
                        trading_pair_id.clone(),
                        String::from("polkadot"),
                        String::from("usd"),
                    )
                });
            client
                .call(&ink_e2e::alice(), create_trading_pair, 0, None)
                .await
                .expect("create trading pair failed");
        }

        async fn alice_grants_bob_as_attestor(
            client: &mut ink_e2e::Client<PolkadotConfig, DefaultEnvironment>,
            contract_id: &AccountId,
        ) {
            // bob is granted as attestor
            let bob_address = ink::primitives::AccountId::from(ink_e2e::bob().public_key().0);
            let grant_role = build_message::<TestOracleRef>(contract_id.clone())
                .call(|oracle| oracle.grant_role(ATTESTOR_ROLE, Some(bob_address)));
            client
                .call(&ink_e2e::alice(), grant_role, 0, None)
                .await
                .expect("grant bob as attestor failed");
        }

        #[ink_e2e::test]
        async fn test_create_trading_pair(mut client: ink_e2e::Client<C, E>) -> E2EResult<()> {
            // given
            let contract_id = alice_instantiates_contract(&mut client).await;

            let trading_pair_id = 10;

            // read the trading pair and check it doesn't exist yet
            let get_trading_pair = build_message::<TestOracleRef>(contract_id.clone())
                .call(|oracle| oracle.get_trading_pair(trading_pair_id));
            let get_res = client
                .call_dry_run(&ink_e2e::bob(), &get_trading_pair, 0, None)
                .await;
            assert_eq!(None, get_res.return_value());

            // bob is not granted as manager => it should not be able to create the trading pair
            let create_trading_pair =
                build_message::<TestOracleRef>(contract_id.clone()).call(|oracle| {
                    oracle.create_trading_pair(
                        trading_pair_id,
                        String::from("polkadot"),
                        String::from("usd"),
                    )
                });
            let result = client
                .call(&ink_e2e::bob(), create_trading_pair, 0, None)
                .await;
            assert!(
                result.is_err(),
                "only manager should not be able to create trading pair"
            );

            // bob is granted as manager
            let bob_address = ink::primitives::AccountId::from(ink_e2e::bob().public_key().0);
            let grant_role = build_message::<TestOracleRef>(contract_id.clone())
                .call(|oracle| oracle.grant_role(MANAGER_ROLE, Some(bob_address)));
            client
                .call(&ink_e2e::alice(), grant_role, 0, None)
                .await
                .expect("grant bob as manager failed");

            let create_trading_pair =
                build_message::<TestOracleRef>(contract_id.clone()).call(|oracle| {
                    oracle.create_trading_pair(
                        trading_pair_id,
                        String::from("polkadot"),
                        String::from("usd"),
                    )
                });
            client
                .call(&ink_e2e::bob(), create_trading_pair, 0, None)
                .await
                .expect("create trading pair failed");

            // then check if the trading pair exists
            let get_trading_pair = build_message::<TestOracleRef>(contract_id.clone())
                .call(|oracle| oracle.get_trading_pair(trading_pair_id));
            let get_res = client
                .call_dry_run(&ink_e2e::bob(), &get_trading_pair, 0, None)
                .await;
            let expected_trading_pair = TradingPair {
                token0: String::from("polkadot"),
                token1: String::from("usd"),
                value: 0,
                nb_updates: 0,
                last_update: 0,
            };
            assert_eq!(Some(expected_trading_pair), get_res.return_value());

            Ok(())
        }

        #[ink_e2e::test]
        async fn test_feed_price(mut client: ink_e2e::Client<C, E>) -> E2EResult<()> {
            // given
            let contract_id = alice_instantiates_contract(&mut client).await;

            let trading_pair_id = 10;

            // create the trading pair
            alice_creates_trading_pair(
                &mut client,
                &contract_id,
                &trading_pair_id
            )
            .await;

            // bob is granted as attestor
            alice_grants_bob_as_attestor(&mut client, &contract_id).await;

            // then bob feeds the price
            let value: u128 = 150_000_000_000_000_000_000;
            let payload = PriceResponseMessage {
                resp_type: TYPE_FEED,
                trading_pair_id,
                price: Some(value),
                err_no: None,
            };
            let actions = vec![HandleActionInput::Reply(payload.encode())];
            let rollup_cond_eq = build_message::<TestOracleRef>(contract_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(vec![], vec![], actions.clone()));
            let result = client
                .call(&ink_e2e::bob(), rollup_cond_eq, 0, None)
                .await
                .expect("rollup cond eq failed");
            // events PriceReceived
            assert!(result.contains_event("Contracts", "ContractEmitted"));

            // and check if the price is filled
            let get_trading_pair = build_message::<TestOracleRef>(contract_id.clone())
                .call(|oracle| oracle.get_trading_pair(trading_pair_id));
            let get_res = client
                .call_dry_run(&ink_e2e::bob(), &get_trading_pair, 0, None)
                .await;
            let trading_pair = get_res.return_value().expect("Trading pair not found");

            assert_eq!(value, trading_pair.value);
            assert_eq!(1, trading_pair.nb_updates);
            assert_ne!(0, trading_pair.last_update);

            Ok(())
        }

        #[ink_e2e::test]
        async fn test_receive_reply(mut client: ink_e2e::Client<C, E>) -> E2EResult<()> {
            // given
            let contract_id = alice_instantiates_contract(&mut client).await;

            let trading_pair_id = 10;

            // create the trading pair
            alice_creates_trading_pair(
                &mut client,
                &contract_id,
                &trading_pair_id
            )
            .await;

            // bob is granted as attestor
            alice_grants_bob_as_attestor(&mut client, &contract_id).await;

            // a price request is sent
            let request_price = build_message::<TestOracleRef>(contract_id.clone())
                .call(|oracle| oracle.request_price(trading_pair_id));
            let result = client
                .call(&ink_e2e::alice(), request_price, 0, None)
                .await
                .expect("Request price should be sent");
            // event MessageQueued
            assert!(result.contains_event("Contracts", "ContractEmitted"));

            let request_id = result.return_value().expect("Request id not found");

            // then a response is received
            let value: u128 = 150_000_000_000_000_000_000;
            let payload = PriceResponseMessage {
                resp_type: TYPE_RESPONSE,
                trading_pair_id,
                price: Some(value),
                err_no: None,
            };
            let actions = vec![
                HandleActionInput::Reply(payload.encode()),
                HandleActionInput::SetQueueHead(request_id + 1),
            ];
            let rollup_cond_eq = build_message::<TestOracleRef>(contract_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(vec![], vec![], actions.clone()));
            let result = client
                .call(&ink_e2e::bob(), rollup_cond_eq, 0, None)
                .await
                .expect("rollup cond eq should be ok");
            // two events : MessageProcessedTo and PricesRecieved
            assert!(result.contains_event("Contracts", "ContractEmitted"));

            // and check if the price is filled
            let get_trading_pair = build_message::<TestOracleRef>(contract_id.clone())
                .call(|oracle| oracle.get_trading_pair(trading_pair_id));
            let get_res = client
                .call_dry_run(&ink_e2e::bob(), &get_trading_pair, 0, None)
                .await;
            let trading_pair = get_res.return_value().expect("Trading pair not found");

            assert_eq!(value, trading_pair.value);
            assert_eq!(1, trading_pair.nb_updates);
            assert_ne!(0, trading_pair.last_update);

            // reply in the future should fail
            let actions = vec![
                HandleActionInput::Reply(payload.encode()),
                HandleActionInput::SetQueueHead(request_id + 2),
            ];
            let rollup_cond_eq = build_message::<TestOracleRef>(contract_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(vec![], vec![], actions.clone()));
            let result = client.call(&ink_e2e::bob(), rollup_cond_eq, 0, None).await;
            assert!(
                result.is_err(),
                "Rollup should fail because we try to pop in the future"
            );

            // reply in the past should fail
            let actions = vec![
                HandleActionInput::Reply(payload.encode()),
                HandleActionInput::SetQueueHead(request_id),
            ];
            let rollup_cond_eq = build_message::<TestOracleRef>(contract_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(vec![], vec![], actions.clone()));
            let result = client.call(&ink_e2e::bob(), rollup_cond_eq, 0, None).await;
            assert!(
                result.is_err(),
                "Rollup should fail because we try to pop in the past"
            );

            Ok(())
        }

        #[ink_e2e::test]
        async fn test_receive_error(mut client: ink_e2e::Client<C, E>) -> E2EResult<()> {
            // given
            let contract_id = alice_instantiates_contract(&mut client).await;

            let trading_pair_id = 10;

            // create the trading pair
            alice_creates_trading_pair(
                &mut client,
                &contract_id,
                &trading_pair_id
            )
            .await;

            // bob is granted as attestor
            alice_grants_bob_as_attestor(&mut client, &contract_id).await;

            // a price request is sent
            let request_price = build_message::<TestOracleRef>(contract_id.clone())
                .call(|oracle| oracle.request_price(trading_pair_id));
            let result = client
                .call(&ink_e2e::alice(), request_price, 0, None)
                .await
                .expect("Request price should be sent");
            // event : MessageQueued
            assert!(result.contains_event("Contracts", "ContractEmitted"));

            let request_id = result.return_value().expect("Request id not found");

            // then a response is received
            let payload = PriceResponseMessage {
                resp_type: TYPE_ERROR,
                trading_pair_id,
                price: None,
                err_no: Some(12356),
            };
            let actions = vec![
                HandleActionInput::Reply(payload.encode()),
                HandleActionInput::SetQueueHead(request_id + 1),
            ];
            let rollup_cond_eq = build_message::<TestOracleRef>(contract_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(vec![], vec![], actions.clone()));
            let result = client
                .call(&ink_e2e::bob(), rollup_cond_eq, 0, None)
                .await
                .expect("we should proceed error message");
            // two events : MessageProcessedTo and PricesReceived
            assert!(result.contains_event("Contracts", "ContractEmitted"));

            Ok(())
        }

        #[ink_e2e::test]
        async fn test_bad_attestor(mut client: ink_e2e::Client<C, E>) -> E2EResult<()> {
            // given
            let contract_id = alice_instantiates_contract(&mut client).await;

            // bob is not granted as attestor => it should not be able to send a message
            let rollup_cond_eq = build_message::<TestOracleRef>(contract_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(vec![], vec![], vec![]));
            let result = client.call(&ink_e2e::bob(), rollup_cond_eq, 0, None).await;
            assert!(
                result.is_err(),
                "only attestor should be able to send messages"
            );

            // bob is granted as attestor
            alice_grants_bob_as_attestor(&mut client, &contract_id).await;

            // then bob is able to send a message
            let rollup_cond_eq = build_message::<TestOracleRef>(contract_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(vec![], vec![], vec![]));
            let result = client
                .call(&ink_e2e::bob(), rollup_cond_eq, 0, None)
                .await
                .expect("rollup cond eq failed");
            // no event
            assert!(!result.contains_event("Contracts", "ContractEmitted"));

            Ok(())
        }

        #[ink_e2e::test]
        async fn test_bad_messages(mut client: ink_e2e::Client<C, E>) -> E2EResult<()> {
            // given
            let contract_id = alice_instantiates_contract(&mut client).await;

            let trading_pair_id = 10;

            // create the trading pair
            alice_creates_trading_pair(
                &mut client,
                &contract_id,
                &trading_pair_id
            )
            .await;

            // bob is granted as attestor
            alice_grants_bob_as_attestor(&mut client, &contract_id).await;

            // then bob sends a message
            let actions = vec![HandleActionInput::Reply(58u128.encode())];
            let rollup_cond_eq = build_message::<TestOracleRef>(contract_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(vec![], vec![], actions.clone()));
            let result = client.call(&ink_e2e::bob(), rollup_cond_eq, 0, None).await;
            assert!(
                result.is_err(),
                "we should not be able to proceed bad messages"
            );

            Ok(())
        }

        #[ink_e2e::test]
        async fn test_optimistic_locking(mut client: ink_e2e::Client<C, E>) -> E2EResult<()> {
            // given
            let contract_id = alice_instantiates_contract(&mut client).await;

            // bob is granted as attestor
            alice_grants_bob_as_attestor(&mut client, &contract_id).await;

            // then bob sends a message
            // from v0 to v1 => it's ok
            let conditions = vec![(123u8.encode(), None)];
            let updates = vec![(123u8.encode(), Some(1u128.encode()))];
            let rollup_cond_eq = build_message::<TestOracleRef>(contract_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(conditions.clone(), updates.clone(), vec![]));
            let result = client.call(&ink_e2e::bob(), rollup_cond_eq, 0, None).await;
            result.expect("This message should be proceed because the condition is met");

            // test idempotency it should fail because the conditions are not met
            let rollup_cond_eq = build_message::<TestOracleRef>(contract_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(conditions.clone(), updates.clone(), vec![]));
            let result = client.call(&ink_e2e::bob(), rollup_cond_eq, 0, None).await;
            assert!(
                result.is_err(),
                "This message should not be proceed because the condition is not met"
            );

            // from v1 to v2 => it's ok
            let conditions = vec![(123u8.encode(), Some(1u128.encode()))];
            let updates = vec![(123u8.encode(), Some(2u128.encode()))];
            let rollup_cond_eq = build_message::<TestOracleRef>(contract_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(conditions.clone(), updates.clone(), vec![]));
            let result = client.call(&ink_e2e::bob(), rollup_cond_eq, 0, None).await;
            result.expect("This message should be proceed because the condition is met");

            // test idempotency it should fail because the conditions are not met
            let rollup_cond_eq = build_message::<TestOracleRef>(contract_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(conditions.clone(), updates.clone(), vec![]));
            let result = client.call(&ink_e2e::bob(), rollup_cond_eq, 0, None).await;
            assert!(
                result.is_err(),
                "This message should not be proceed because the condition is not met"
            );

            Ok(())
        }

        ///
        /// Test the meta transactions
        /// Alice is the owner
        /// Bob is the attestor
        /// Charlie is the sender (ie the payer)
        ///
        #[ink_e2e::test]
        async fn test_meta_tx_rollup_cond_eq(mut client: ink_e2e::Client<C, E>) -> E2EResult<()> {
            let contract_id = alice_instantiates_contract(&mut client).await;

            // Bob is the attestor
            // use the ecsda account because we are not able to verify the sr25519 signature
            let from = ink::primitives::AccountId::from(
                Signer::<PolkadotConfig>::account_id(&subxt_signer::ecdsa::dev::bob()).0,
            );

            // add the role => it should be succeed
            let grant_role = build_message::<TestOracleRef>(contract_id.clone())
                .call(|oracle| oracle.grant_role(ATTESTOR_ROLE, Some(from)));
            client
                .call(&ink_e2e::alice(), grant_role, 0, None)
                .await
                .expect("grant the attestor failed");

            // prepare the meta transaction
            let data = RollupCondEqMethodParams::encode(&(vec![], vec![], vec![]));
            let prepare_meta_tx = build_message::<TestOracleRef>(contract_id.clone())
                .call(|oracle| oracle.prepare(from, data.clone()));
            let result = client
                .call(&ink_e2e::bob(), prepare_meta_tx, 0, None)
                .await
                .expect("We should be able to prepare the meta tx");

            let (request, _hash) = result
                .return_value()
                .expect("Expected value when preparing meta tx");

            assert_eq!(0, request.nonce);
            assert_eq!(from, request.from);
            assert_eq!(contract_id, request.to);
            assert_eq!(&data, &request.data);

            // Bob signs the message
            let keypair = subxt_signer::ecdsa::dev::bob();
            let signature = keypair.sign(&scale::Encode::encode(&request)).0;

            // do the meta tx: charlie sends the message
            let meta_tx_rollup_cond_eq = build_message::<TestOracleRef>(contract_id.clone())
                .call(|oracle| oracle.meta_tx_rollup_cond_eq(request.clone(), signature));
            client
                .call(&ink_e2e::charlie(), meta_tx_rollup_cond_eq, 0, None)
                .await
                .expect("meta tx rollup cond eq should not failed");

            // do it again => it must failed
            let meta_tx_rollup_cond_eq = build_message::<TestOracleRef>(contract_id.clone())
                .call(|oracle| oracle.meta_tx_rollup_cond_eq(request.clone(), signature));
            let result = client
                .call(&ink_e2e::charlie(), meta_tx_rollup_cond_eq, 0, None)
                .await;
            assert!(
                result.is_err(),
                "This message should not be proceed because the nonce is obsolete"
            );

            Ok(())
        }
    }
}

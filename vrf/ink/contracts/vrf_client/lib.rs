#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[openbrush::implementation(Ownable, AccessControl, Upgradeable)]
#[openbrush::contract]
pub mod vrf_client {
    use ink::codegen::{EmitEvent, Env};
    use ink::env::hash::{Blake2x256, HashOutput};
    use ink::prelude::vec::Vec;
    use ink::storage::Mapping;
    use openbrush::contracts::access_control::*;
    use openbrush::contracts::ownable::*;
    use openbrush::traits::Storage;
    use scale::{Decode, Encode};

    use phat_rollup_anchor_ink::traits::{
        kv_store, kv_store::*, message_queue, message_queue::*, meta_transaction,
        meta_transaction::*, rollup_anchor, rollup_anchor::*,
    };

    pub const REQUESTOR_ROLE: RoleType = ink::selector_id!("REQUESTOR_ROLE");

    /// Events emitted when a random value is received
    #[ink(event)]
    pub struct RandomValueReceived {
        /// id of the requestor
        requestor_id: AccountId,
        /// nonce of the requestor
        requestor_nonce: u128,
        /// random_value
        random_value: u128,
    }

    /// Events emitted when an error is received
    #[ink(event)]
    pub struct ErrorReceived {
        /// id of the requestor
        requestor_id: AccountId,
        /// nonce of the requestor
        requestor_nonce: u128,
        /// error number
        err_no: Vec<u8>,
    }

    /// Errors occurred in the contract
    #[derive(Encode, Decode, Debug)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum ContractError {
        AccessControlError(AccessControlError),
        MessageQueueError(MessageQueueError),
        MetaTransactionError(MetaTransactionError),
        FailedToDecode,
    }

    /// convertor from MessageQueueError to ContractError
    impl From<MessageQueueError> for ContractError {
        fn from(error: MessageQueueError) -> Self {
            ContractError::MessageQueueError(error)
        }
    }
    /// convertor from MessageQueueError to ContractError
    impl From<AccessControlError> for ContractError {
        fn from(error: AccessControlError) -> Self {
            ContractError::AccessControlError(error)
        }
    }
    /// convertor from MetaTxError to ContractError
    impl From<MetaTransactionError> for ContractError {
        fn from(error: MetaTransactionError) -> Self {
            ContractError::MetaTransactionError(error)
        }
    }

    /// Message to request the random value
    /// message pushed in the queue by this contract and read by the offchain rollup
    #[derive(Encode, Decode)]
    struct RandomValueRequestMessage {
        /// id of the requestor
        requestor_id: AccountId,
        /// nonce of the requestor
        requestor_nonce: Nonce,
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
    #[derive(Default, Storage)]
    pub struct VrfClient {
        #[storage_field]
        ownable: ownable::Data,
        #[storage_field]
        access: access_control::Data,
        #[storage_field]
        kv_store: kv_store::Data,
        #[storage_field]
        meta_transaction: meta_transaction::Data,
        /// Nonce of the requestor.
        requestor_nonces: Mapping<AccountId, Nonce>,
        /// hash of the request by (requestor,nonce)
        hash_requests: Mapping<(AccountId, Nonce), Hash>,
        /// last random values by requestor
        last_values: Mapping<AccountId, u128>,
    }

    impl VrfClient {
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
        pub fn get_requestor_nonce(&mut self, requestor: AccountId) -> Result<Nonce, ContractError> {
            let nonce = self.requestor_nonces.get(&requestor).unwrap_or(0);
            Ok(nonce)
        }

        #[ink(message)]
        #[openbrush::modifiers(access_control::only_role(REQUESTOR_ROLE))]
        pub fn get_last_value(&mut self) -> Result<Option<u128>, ContractError> {
            let requestor = self.env().caller();
            let value = self.last_values.get(&requestor);
            Ok(value)
        }

        #[ink(message)]
        #[openbrush::modifiers(access_control::only_role(REQUESTOR_ROLE))]
        pub fn request_random_value(
            &mut self,
            min: u128,
            max: u128,
        ) -> Result<QueueIndex, ContractError> {
            let requestor_id = self.env().caller();
            // get the current nonce
            let requestor_nonce = self.requestor_nonces.get(&requestor_id).unwrap_or(0);
            // increment the nonce
            let requestor_nonce = requestor_nonce + 1;

            // push the message in the queue
            let message = RandomValueRequestMessage {
                requestor_id,
                requestor_nonce,
                min,
                max,
            };
            let message_id = self.push_message(&message)?;

            // hash the message
            let mut hash = <Blake2x256 as HashOutput>::Type::default();
            ink::env::hash_encoded::<Blake2x256, _>(&message, &mut hash);
            // save the hash
            let hash : Hash =  hash.into();
            self.hash_requests.insert((&requestor_id, &requestor_nonce), &hash);

            // update the nonce
            self.requestor_nonces.insert(&requestor_id, &requestor_nonce);

            Ok(message_id)
        }

        #[ink(message)]
        pub fn register_attestor(
            &mut self,
            account_id: AccountId,
            ecdsa_public_key: [u8; 33],
        ) -> Result<(), ContractError> {
            AccessControl::grant_role(self, ATTESTOR_ROLE, Some(account_id))?;
            self.register_ecdsa_public_key(account_id, ecdsa_public_key)?;
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

        #[ink(message)]
        pub fn get_requestor_role(&self) -> RoleType {
            REQUESTOR_ROLE
        }
    }

    impl KvStore for VrfClient {}
    impl MessageQueue for VrfClient {}
    impl RollupAnchor for VrfClient {}
    impl MetaTransaction for VrfClient {}

    impl rollup_anchor::MessageHandler for VrfClient {
        fn on_message_received(&mut self, action: Vec<u8>) -> Result<(), RollupAnchorError> {
            // parse the response
            let message: RandomValueResponseMessage =
                Decode::decode(&mut &action[..]).or(Err(RollupAnchorError::FailedToDecode))?;

            // get the previous message
            /*
            let request: RandomValueRequestMessage = self
                .get_message(message.request_id)?
                .ok_or(RollupAnchorError::FailedToDecode)?;
             */

            let requestor_id = message.request.requestor_id;
            let requestor_nonce = message.request.requestor_nonce;

            // hash the message
            let mut hash = <Blake2x256 as HashOutput>::Type::default();
            ink::env::hash_encoded::<Blake2x256, _>(&message.request, &mut hash);
            let hash : Hash =  hash.into();
            let expected_hash = self.hash_requests.get((&requestor_id, &requestor_nonce))
                .ok_or(RollupAnchorError::ConditionNotMet)?;// TODO improve the error
            // check the hash
            if hash != expected_hash {
                return Err(RollupAnchorError::ConditionNotMet); // TODO improve the error
            }
            // remove the ongoing hash
            self.hash_requests.remove((&requestor_id, &requestor_nonce));

            // handle the response
            if message.resp_type == TYPE_RESPONSE {
                // we received the random value
                // TODO check if the random value is right
                let random_value = message
                    .random_value
                    .ok_or(RollupAnchorError::FailedToDecode)?;

                // register the info
                self.last_values.insert(&requestor_id, &random_value);

                // emmit te event
                self.env().emit_event(RandomValueReceived {
                    requestor_id,
                    requestor_nonce,
                    random_value,
                });
            } else if message.resp_type == TYPE_ERROR {
                // we received an error
                self.env().emit_event(ErrorReceived {
                    requestor_id,
                    requestor_nonce,
                    err_no: message.error.unwrap_or_default(),
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

    impl message_queue::EventBroadcaster for VrfClient {
        fn emit_event_message_queued(&self, id: u32, data: Vec<u8>) {
            self.env().emit_event(MessageQueued { id, data });
        }

        fn emit_event_message_processed_to(&self, id: u32) {
            self.env().emit_event(MessageProcessedTo { id });
        }
    }

    impl meta_transaction::EventBroadcaster for VrfClient {
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
        use openbrush::contracts::access_control::accesscontrol_external::AccessControl;

        use ink_e2e::build_message;
        use phat_rollup_anchor_ink::traits::{
            meta_transaction::metatransaction_external::MetaTransaction,
            rollup_anchor::rollupanchor_external::RollupAnchor,
        };

        type E2EResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

        #[ink_e2e::test]
        async fn test_receive_reply(mut client: ink_e2e::Client<C, E>) -> E2EResult<()> {
            // given
            let constructor = VrfClientRef::new();
            let contract_acc_id = client
                .instantiate("vrf_client", &ink_e2e::alice(), constructor, 0, None)
                .await
                .expect("instantiate failed")
                .account_id;

            // bob is granted as attestor
            let bob_address = ink::primitives::AccountId::from(ink_e2e::bob().public_key().0);
            let grant_role = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.grant_role(ATTESTOR_ROLE, Some(bob_address)));
            client
                .call(&ink_e2e::alice(), grant_role, 0, None)
                .await
                .expect("grant bob as attestor failed");

            // charlie is granted as requestor
            let charlie_address = ink::primitives::AccountId::from(ink_e2e::charlie().public_key().0);
            let grant_role = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.grant_role(REQUESTOR_ROLE, Some(charlie_address)));
            client
                .call(&ink_e2e::alice(), grant_role, 0, None)
                .await
                .expect("grant charlie as requestor failed");

            // a price request is sent
            let request_random_value = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.request_random_value(100_u128, 1000_u128));
            let result = client
                .call(&ink_e2e::charlie(), request_random_value, 0, None)
                .await
                .expect("Request price should be sent");
            // event MessageQueued
            assert!(result.contains_event("Contracts", "ContractEmitted"));

            let request_id = result.return_value().expect("Request id not found");

            // then a response is received
            let random_value = Some(131_u128);
            let payload = RandomValueResponseMessage {
                resp_type: TYPE_RESPONSE,
                request: RandomValueRequestMessage {
                    requestor_id: ink::primitives::AccountId::from(ink_e2e::charlie().public_key().0),
                    requestor_nonce: 1,
                    min: 100_u128,
                    max: 1000_u128,
                },
                random_value,
                error: None,
            };
            let actions = vec![
                HandleActionInput {
                    action_type: ACTION_REPLY,
                    //id: Some(request_id),
                    id: None,
                    action: Some(payload.encode()),
                    address: None,
                },
                HandleActionInput {
                    action_type: ACTION_SET_QUEUE_HEAD,
                    id: Some(request_id + 1),
                    action: None,
                    address: None,
                },
            ];
            let rollup_cond_eq = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(vec![], vec![], actions.clone()));
            let result = client
                .call(&ink_e2e::bob(), rollup_cond_eq, 0, None)
                .await
                .expect("rollup cond eq should be ok");
            // two events : MessageProcessedTo and RandomValueReceived
            assert!(result.contains_event("Contracts", "ContractEmitted"));

            // and check if the random value is filled
            let get_last_value = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.get_last_value());
            let get_res = client
                .call_dry_run(&ink_e2e::charlie(), &get_last_value, 0, None)
                .await;
            let last_value = get_res.return_value().expect("Last value not found");

            assert_eq!(last_value, Some(131));

            // reply in the future should fail
            let actions = vec![
                HandleActionInput {
                    action_type: ACTION_REPLY,
                    //id: Some(request_id),
                    id: None,
                    action: Some(payload.encode()),
                    address: None,
                },
                HandleActionInput {
                    action_type: ACTION_SET_QUEUE_HEAD,
                    id: Some(request_id + 2),
                    action: None,
                    address: None,
                },
            ];
            let rollup_cond_eq = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(vec![], vec![], actions.clone()));
            let result = client.call(&ink_e2e::bob(), rollup_cond_eq, 0, None).await;
            assert!(
                result.is_err(),
                "Rollup should fail because we try to pop in the future"
            );

            // reply in the past should fail
            let actions = vec![
                HandleActionInput {
                    action_type: ACTION_REPLY,
                    //id: Some(request_id),
                    id: None,
                    action: Some(payload.encode()),
                    address: None,
                },
                HandleActionInput {
                    action_type: ACTION_SET_QUEUE_HEAD,
                    id: Some(request_id),
                    action: None,
                    address: None,
                },
            ];
            let rollup_cond_eq = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(vec![], vec![], actions.clone()));
            let result = client.call(&ink_e2e::bob(), rollup_cond_eq, 0, None).await;
            assert!(
                result.is_err(),
                "Rollup should fail because we try to pop in the past"
            );

            Ok(())
        }


        #[ink_e2e::test]
        async fn test_many_sequential_requests_replies(mut client: ink_e2e::Client<C, E>) -> E2EResult<()> {
            // given
            let constructor = VrfClientRef::new();
            let contract_acc_id = client
                .instantiate("vrf_client", &ink_e2e::alice(), constructor, 0, None)
                .await
                .expect("instantiate failed")
                .account_id;

            // bob is granted as attestor
            let bob_address = ink::primitives::AccountId::from(ink_e2e::bob().public_key().0);
            let grant_role = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.grant_role(ATTESTOR_ROLE, Some(bob_address)));
            client
                .call(&ink_e2e::alice(), grant_role, 0, None)
                .await
                .expect("grant bob as attestor failed");

            // charlie is granted as requestor
            let charlie_address = ink::primitives::AccountId::from(ink_e2e::charlie().public_key().0);
            let grant_role = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.grant_role(REQUESTOR_ROLE, Some(charlie_address)));
            client
                .call(&ink_e2e::alice(), grant_role, 0, None)
                .await
                .expect("grant charlie as requestor failed");

            // a request is sent
            let request_random_value = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.request_random_value(0_u128, 1000000000_u128));
            let result = client
                .call(&ink_e2e::charlie(), request_random_value, 0, None)
                .await
                .expect("Request random value should be sent");
            // event MessageQueued
            assert!(result.contains_event("Contracts", "ContractEmitted"));

            let request_id = result.return_value().expect("Request id not found");

            // then a response is received
            let random_value = Some(131_u128);
            let payload = RandomValueResponseMessage {
                resp_type: TYPE_RESPONSE,
                request: RandomValueRequestMessage {
                    requestor_id: ink::primitives::AccountId::from(ink_e2e::charlie().public_key().0),
                    requestor_nonce: 1,
                    min: 0_u128,
                    max: 1000000000_u128,
                },
                random_value,
                error: None,
            };
            let actions = vec![
                HandleActionInput {
                    action_type: ACTION_REPLY,
                    //id: Some(request_id),
                    id: None,
                    action: Some(payload.encode()),
                    address: None,
                },
                HandleActionInput {
                    action_type: ACTION_SET_QUEUE_HEAD,
                    id: Some(request_id + 1),
                    action: None,
                    address: None,
                },
            ];
            let rollup_cond_eq = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(vec![], vec![], actions.clone()));
            let result = client
                .call(&ink_e2e::bob(), rollup_cond_eq, 0, None)
                .await
                .expect("rollup cond eq should be ok");
            // two events : MessageProcessedTo and RandomValueReceived
            assert!(result.contains_event("Contracts", "ContractEmitted"));

            // and check if the random value is filled
            let get_last_value = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.get_last_value());
            let get_res = client
                .call_dry_run(&ink_e2e::charlie(), &get_last_value, 0, None)
                .await;
            let last_value = get_res.return_value().expect("Last value not found");

            assert_eq!(last_value, Some(131));

            // another request is sent
            let request_random_value = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.request_random_value(50_u128, 100_u128));
            let result = client
                .call(&ink_e2e::charlie(), request_random_value, 0, None)
                .await
                .expect("Request random value should be sent");
            // event MessageQueued
            assert!(result.contains_event("Contracts", "ContractEmitted"));

            let request_id = result.return_value().expect("Request id not found");

            // another response is received
            let random_value = Some(75_u128);
            let payload = RandomValueResponseMessage {
                resp_type: TYPE_RESPONSE,
                request: RandomValueRequestMessage {
                    requestor_id: ink::primitives::AccountId::from(ink_e2e::charlie().public_key().0),
                    requestor_nonce: 2,
                    min: 50_u128,
                    max: 100_u128,
                },
                random_value,
                error: None,
            };
            let actions = vec![
                HandleActionInput {
                    action_type: ACTION_REPLY,
                    //id: Some(request_id),
                    id: None,
                    action: Some(payload.encode()),
                    address: None,
                },
                HandleActionInput {
                    action_type: ACTION_SET_QUEUE_HEAD,
                    id: Some(request_id + 1),
                    action: None,
                    address: None,
                },
            ];
            let rollup_cond_eq = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(vec![], vec![], actions.clone()));
            let result = client
                .call(&ink_e2e::bob(), rollup_cond_eq, 0, None)
                .await
                .expect("rollup cond eq should be ok");
            // two events : MessageProcessedTo and RandomValueReceived
            assert!(result.contains_event("Contracts", "ContractEmitted"));

            // and check if the random value is filled
            let get_last_value = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.get_last_value());
            let get_res = client
                .call_dry_run(&ink_e2e::charlie(), &get_last_value, 0, None)
                .await;
            let last_value = get_res.return_value().expect("Last value not found");

            assert_eq!(last_value, Some(75_u128));

            Ok(())
        }



        #[ink_e2e::test]
        async fn test_concurrent_requests_replies(mut client: ink_e2e::Client<C, E>) -> E2EResult<()> {
            // given
            let constructor = VrfClientRef::new();
            let contract_acc_id = client
                .instantiate("vrf_client", &ink_e2e::alice(), constructor, 0, None)
                .await
                .expect("instantiate failed")
                .account_id;

            // bob is granted as attestor
            let bob_address = ink::primitives::AccountId::from(ink_e2e::bob().public_key().0);
            let grant_role = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.grant_role(ATTESTOR_ROLE, Some(bob_address)));
            client
                .call(&ink_e2e::alice(), grant_role, 0, None)
                .await
                .expect("grant bob as attestor failed");

            // charlie is granted as requestor
            let charlie_address = ink::primitives::AccountId::from(ink_e2e::charlie().public_key().0);
            let grant_role = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.grant_role(REQUESTOR_ROLE, Some(charlie_address)));
            client
                .call(&ink_e2e::alice(), grant_role, 0, None)
                .await
                .expect("grant charlie as requestor failed");

            // a first request is sent
            let request_random_value = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.request_random_value(0_u128, 1000000000_u128));
            let result = client
                .call(&ink_e2e::charlie(), request_random_value, 0, None)
                .await
                .expect("Request random value should be sent");
            // event MessageQueued
            assert!(result.contains_event("Contracts", "ContractEmitted"));

            let request_id_1 = result.return_value().expect("Request id not found");

            // another request is sent
            let request_random_value = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.request_random_value(0_u128, 50_u128));
            let result = client
                .call(&ink_e2e::charlie(), request_random_value, 0, None)
                .await
                .expect("Request random value should be sent");
            // event MessageQueued
            assert!(result.contains_event("Contracts", "ContractEmitted"));

            let request_id_2 = result.return_value().expect("Request id not found");

            // then a response is received
            let random_value = Some(131_u128);
            let payload = RandomValueResponseMessage {
                resp_type: TYPE_RESPONSE,
                request: RandomValueRequestMessage {
                    requestor_id: ink::primitives::AccountId::from(ink_e2e::charlie().public_key().0),
                    requestor_nonce: 1,
                    min: 0_u128,
                    max: 1000000000_u128,
                },
                random_value,
                error: None,
            };
            let actions = vec![
                HandleActionInput {
                    action_type: ACTION_REPLY,
                    //id: Some(request_id_1),
                    id: None,
                    action: Some(payload.encode()),
                    address: None,
                },
                HandleActionInput {
                    action_type: ACTION_SET_QUEUE_HEAD,
                    id: Some(request_id_1 + 1),
                    action: None,
                    address: None,
                },
            ];
            let rollup_cond_eq = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(vec![], vec![], actions.clone()));
            let result = client
                .call(&ink_e2e::bob(), rollup_cond_eq, 0, None)
                .await
                .expect("rollup cond eq should be ok");
            // two events : MessageProcessedTo and RandomValueReceived
            assert!(result.contains_event("Contracts", "ContractEmitted"));

            // and check if the random value is filled
            let get_last_value = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.get_last_value());
            let get_res = client
                .call_dry_run(&ink_e2e::charlie(), &get_last_value, 0, None)
                .await;
            let last_value = get_res.return_value().expect("Last value not found");

            assert_eq!(last_value, Some(131));

            // another response is received
            let random_value = Some(25_u128);
            let payload = RandomValueResponseMessage {
                resp_type: TYPE_RESPONSE,
                request: RandomValueRequestMessage {
                    requestor_id: ink::primitives::AccountId::from(ink_e2e::charlie().public_key().0),
                    requestor_nonce: 2,
                    min: 0_u128,
                    max: 50_u128,
                },
                random_value,
                error: None,
            };
            let actions = vec![
                HandleActionInput {
                    action_type: ACTION_REPLY,
                    //id: Some(request_id_2),
                    id: None,
                    action: Some(payload.encode()),
                    address: None,
                },
                HandleActionInput {
                    action_type: ACTION_SET_QUEUE_HEAD,
                    id: Some(request_id_2 + 1),
                    action: None,
                    address: None,
                },
            ];
            let rollup_cond_eq = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(vec![], vec![], actions.clone()));
            let result = client
                .call(&ink_e2e::bob(), rollup_cond_eq, 0, None)
                .await
                .expect("rollup cond eq should be ok");
            // two events : MessageProcessedTo and RandomValueReceived
            assert!(result.contains_event("Contracts", "ContractEmitted"));

            // and check if the random value is filled
            let get_last_value = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.get_last_value());
            let get_res = client
                .call_dry_run(&ink_e2e::charlie(), &get_last_value, 0, None)
                .await;
            let last_value = get_res.return_value().expect("Last value not found");

            assert_eq!(last_value, Some(25_u128));

            Ok(())
        }


        #[ink_e2e::test]
        async fn test_bad_hash(mut client: ink_e2e::Client<C, E>) -> E2EResult<()> {
            // given
            let constructor = VrfClientRef::new();
            let contract_acc_id = client
                .instantiate("vrf_client", &ink_e2e::alice(), constructor, 0, None)
                .await
                .expect("instantiate failed")
                .account_id;

            // bob is granted as attestor
            let bob_address = ink::primitives::AccountId::from(ink_e2e::bob().public_key().0);
            let grant_role = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.grant_role(ATTESTOR_ROLE, Some(bob_address)));
            client
                .call(&ink_e2e::alice(), grant_role, 0, None)
                .await
                .expect("grant bob as attestor failed");

            // charlie is granted as requestor
            let charlie_address = ink::primitives::AccountId::from(ink_e2e::charlie().public_key().0);
            let grant_role = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.grant_role(REQUESTOR_ROLE, Some(charlie_address)));
            client
                .call(&ink_e2e::alice(), grant_role, 0, None)
                .await
                .expect("grant charlie as requestor failed");

            // a request is sent
            let request_random_value = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.request_random_value(0_u128, 1000000000_u128));
            let result = client
                .call(&ink_e2e::charlie(), request_random_value, 0, None)
                .await
                .expect("Request random value should be sent");
            // event MessageQueued
            assert!(result.contains_event("Contracts", "ContractEmitted"));

            let request_id = result.return_value().expect("Request id not found");

            // then a response is received
            let random_value = Some(51_u128);
            let payload = RandomValueResponseMessage {
                resp_type: TYPE_RESPONSE,
                request: RandomValueRequestMessage {
                    requestor_id: ink::primitives::AccountId::from(ink_e2e::charlie().public_key().0),
                    requestor_nonce: 1,
                    min: 51_u128, // bad rpc that update the min and max values
                    max: 51_u128,
                },
                random_value,
                error: None,
            };
            let actions = vec![
                HandleActionInput {
                    action_type: ACTION_REPLY,
                    //id: Some(request_id),
                    id: None,
                    action: Some(payload.encode()),
                    address: None,
                },
                HandleActionInput {
                    action_type: ACTION_SET_QUEUE_HEAD,
                    id: Some(request_id + 1),
                    action: None,
                    address: None,
                },
            ];
            let rollup_cond_eq = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(vec![], vec![], actions.clone()));
            let result = client
                .call(&ink_e2e::bob(), rollup_cond_eq, 0, None)
                .await;
            assert!(
                result.is_err(),
                "We should not accept response with bad initial request"
            );

            Ok(())
        }


        #[ink_e2e::test]
        async fn test_receive_error(mut client: ink_e2e::Client<C, E>) -> E2EResult<()> {
            // given
            let constructor = VrfClientRef::new();
            let contract_acc_id = client
                .instantiate("vrf_client", &ink_e2e::alice(), constructor, 0, None)
                .await
                .expect("instantiate failed")
                .account_id;

            // bob is granted as attestor
            let bob_address = ink::primitives::AccountId::from(ink_e2e::bob().public_key().0);
            let grant_role = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.grant_role(ATTESTOR_ROLE, Some(bob_address)));
            client
                .call(&ink_e2e::alice(), grant_role, 0, None)
                .await
                .expect("grant bob as attestor failed");

            // charlie is granted as requestor
            let charlie_address = ink::primitives::AccountId::from(ink_e2e::charlie().public_key().0);
            let grant_role = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.grant_role(REQUESTOR_ROLE, Some(charlie_address)));
            client
                .call(&ink_e2e::alice(), grant_role, 0, None)
                .await
                .expect("grant charlie as requestor failed");

            // a random value is requested
            let request_random_value = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.request_random_value(100_u128, 1000_u128));
            let result = client
                .call(&ink_e2e::charlie(), request_random_value, 0, None)
                .await
                .expect("Request price should be sent");
            // event MessageQueued
            assert!(result.contains_event("Contracts", "ContractEmitted"));

            let request_id = result.return_value().expect("Request id not found");

            // then a response is received
            let payload = RandomValueResponseMessage {
                resp_type: TYPE_ERROR,
                request: RandomValueRequestMessage {
                    requestor_id: ink::primitives::AccountId::from(ink_e2e::charlie().public_key().0),
                    requestor_nonce: 1,
                    min: 100_u128,
                    max: 1000_u128,
                },
                error: Some(12356.encode()),
                random_value: None,
            };
            let actions = vec![
                HandleActionInput {
                    action_type: ACTION_REPLY,
                    id: None,
                    action: Some(payload.encode()),
                    address: None,
                },
                HandleActionInput {
                    action_type: ACTION_SET_QUEUE_HEAD,
                    id: Some(request_id + 1),
                    action: None,
                    address: None,
                },
            ];
            let rollup_cond_eq = build_message::<VrfClientRef>(contract_acc_id.clone())
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
            let constructor = VrfClientRef::new();
            let contract_acc_id = client
                .instantiate("vrf_client", &ink_e2e::alice(), constructor, 0, None)
                .await
                .expect("instantiate failed")
                .account_id;

            // bob is not granted as attestor => it should not be able to send a message
            let rollup_cond_eq = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(vec![], vec![], vec![]));
            let result = client.call(&ink_e2e::bob(), rollup_cond_eq, 0, None).await;
            assert!(
                result.is_err(),
                "only attestor should be able to send messages"
            );

            // bob is granted as attestor
            let bob_address = ink::primitives::AccountId::from(ink_e2e::bob().public_key().0);
            let grant_role = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.grant_role(ATTESTOR_ROLE, Some(bob_address)));
            client
                .call(&ink_e2e::alice(), grant_role, 0, None)
                .await
                .expect("grant bob as attestor failed");

            // then bob is able to send a message
            let rollup_cond_eq = build_message::<VrfClientRef>(contract_acc_id.clone())
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
            let constructor = VrfClientRef::new();
            let contract_acc_id = client
                .instantiate("vrf_client", &ink_e2e::alice(), constructor, 0, None)
                .await
                .expect("instantiate failed")
                .account_id;

            // bob is granted as attestor
            let bob_address = ink::primitives::AccountId::from(ink_e2e::bob().public_key().0);
            let grant_role = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.grant_role(ATTESTOR_ROLE, Some(bob_address)));
            client
                .call(&ink_e2e::alice(), grant_role, 0, None)
                .await
                .expect("grant bob as attestor failed");

            let actions = vec![HandleActionInput {
                action_type: ACTION_REPLY,
                id: None,
                action: Some(58u128.encode()),
                address: None,
            }];
            let rollup_cond_eq = build_message::<VrfClientRef>(contract_acc_id.clone())
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
            let constructor = VrfClientRef::new();
            let contract_acc_id = client
                .instantiate("vrf_client", &ink_e2e::alice(), constructor, 0, None)
                .await
                .expect("instantiate failed")
                .account_id;

            // bob is granted as attestor
            let bob_address = ink::primitives::AccountId::from(ink_e2e::bob().public_key().0);
            let grant_role = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.grant_role(ATTESTOR_ROLE, Some(bob_address)));
            client
                .call(&ink_e2e::alice(), grant_role, 0, None)
                .await
                .expect("grant bob as attestor failed");

            // then bob sends a message
            // from v0 to v1 => it's ok
            let conditions = vec![(123u8.encode(), None)];
            let updates = vec![(123u8.encode(), Some(1u128.encode()))];
            let rollup_cond_eq = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(conditions.clone(), updates.clone(), vec![]));
            let result = client.call(&ink_e2e::bob(), rollup_cond_eq, 0, None).await;
            result.expect("This message should be proceed because the condition is met");

            // test idempotency it should fail because the conditions are not met
            let rollup_cond_eq = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(conditions.clone(), updates.clone(), vec![]));
            let result = client.call(&ink_e2e::bob(), rollup_cond_eq, 0, None).await;
            assert!(
                result.is_err(),
                "This message should not be proceed because the condition is not met"
            );

            // from v1 to v2 => it's ok
            let conditions = vec![(123u8.encode(), Some(1u128.encode()))];
            let updates = vec![(123u8.encode(), Some(2u128.encode()))];
            let rollup_cond_eq = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(conditions.clone(), updates.clone(), vec![]));
            let result = client.call(&ink_e2e::bob(), rollup_cond_eq, 0, None).await;
            result.expect("This message should be proceed because the condition is met");

            // test idempotency it should fail because the conditions are not met
            let rollup_cond_eq = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(conditions.clone(), updates.clone(), vec![]));
            let result = client.call(&ink_e2e::bob(), rollup_cond_eq, 0, None).await;
            assert!(
                result.is_err(),
                "This message should not be proceed because the condition is not met"
            );

            Ok(())
        }

        #[ink_e2e::test]
        async fn test_prepare_meta_tx(mut client: ink_e2e::Client<C, E>) -> E2EResult<()> {
            let constructor = VrfClientRef::new();
            let contract_acc_id = client
                .instantiate("vrf_client", &ink_e2e::bob(), constructor, 0, None)
                .await
                .expect("instantiate failed")
                .account_id;

            // register the ecda public key because I am not able to retrieve if from the account id
            // Alice
            let from =
                ink::primitives::AccountId::from(ink_e2e::alice().public_key().0);
            let ecdsa_public_key: [u8; 33] = hex_literal::hex!(
                "037051bed73458951b45ca6376f4096c85bf1a370da94d5336d04867cfaaad019e"
            );

            let register_ecdsa_public_key = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.register_ecdsa_public_key(from, ecdsa_public_key));
            client
                .call(&ink_e2e::bob(), register_ecdsa_public_key, 0, None)
                .await
                .expect("We should be able to register the ecdsa public key");

            // prepare the meta transaction
            let data = u8::encode(&5);
            let prepare_meta_tx = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.prepare(from, data.clone()));
            let result = client
                .call(&ink_e2e::bob(), prepare_meta_tx, 0, None)
                .await
                .expect("We should be able to prepare the meta tx");

            let (request, hash) = result
                .return_value()
                .expect("Expected value when preparing meta tx");

            assert_eq!(0, request.nonce);
            assert_eq!(from, request.from);
            assert_eq!(&data, &request.data);

            let expected_hash = hex_literal::hex!(
                "17cb4f6eae2f95ba0fbaee9e0e51dc790fe752e7386b72dcd93b9669450c2ccf"
            );
            assert_eq!(&expected_hash, &hash.as_ref());

            Ok(())
        }

        ///
        /// Test the meta transactions
        /// Charlie is the owner
        /// Alice is the attestor
        /// Bob is the sender (ie the payer)
        ///
        #[ink_e2e::test]
        async fn test_meta_tx_rollup_cond_eq(mut client: ink_e2e::Client<C, E>) -> E2EResult<()> {
            let constructor = VrfClientRef::new();
            let contract_acc_id = client
                .instantiate("vrf_client", &ink_e2e::charlie(), constructor, 0, None)
                .await
                .expect("instantiate failed")
                .account_id;

            // register the ecda public key because I am not able to retrieve if from the account id
            // Alice is the attestor
            let from =
                ink::primitives::AccountId::from(ink_e2e::alice().public_key().0);
            let ecdsa_public_key: [u8; 33] = hex_literal::hex!(
                "037051bed73458951b45ca6376f4096c85bf1a370da94d5336d04867cfaaad019e"
            );

            let register_ecdsa_public_key = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.register_ecdsa_public_key(from, ecdsa_public_key));
            client
                .call(&ink_e2e::charlie(), register_ecdsa_public_key, 0, None)
                .await
                .expect("We should be able to register the ecdsa public key");

            // add the role => it should be succeed
            let grant_role = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.grant_role(ATTESTOR_ROLE, Some(from)));
            client
                .call(&ink_e2e::charlie(), grant_role, 0, None)
                .await
                .expect("grant the attestor failed");

            // prepare the meta transaction
            let data = RolupCondEqMethodParams::encode(&(vec![], vec![], vec![]));
            let prepare_meta_tx = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.prepare(from, data.clone()));
            let result = client
                .call(&ink_e2e::bob(), prepare_meta_tx, 0, None)
                .await
                .expect("We should be able to prepare the meta tx");

            let (request, hash) = result
                .return_value()
                .expect("Expected value when preparing meta tx");

            assert_eq!(0, request.nonce);
            assert_eq!(from, request.from);
            assert_eq!(&data, &request.data);

            let expected_hash = hex_literal::hex!(
                "c91f57305dc05a66f1327352d55290a250eb61bba8e3cf8560a4b8e7d172bb54"
            );
            assert_eq!(&expected_hash, &hash.as_ref());

            // signature by Alice of previous hash
            let signature : [u8; 65] = hex_literal::hex!("c9a899bc8daa98fd1e819486c57f9ee889d035e8d0e55c04c475ca32bb59389b284d18d785a9db1bdd72ce74baefe6a54c0aa2418b14f7bc96232fa4bf42946600");

            // do the meta tx
            let meta_tx_rollup_cond_eq = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.meta_tx_rollup_cond_eq(request.clone(), signature));
            client
                .call(&ink_e2e::bob(), meta_tx_rollup_cond_eq, 0, None)
                .await
                .expect("meta tx rollup cond eq should not failed");

            // do it again => it must failed
            let meta_tx_rollup_cond_eq = build_message::<VrfClientRef>(contract_acc_id.clone())
                .call(|oracle| oracle.meta_tx_rollup_cond_eq(request.clone(), signature));
            let result = client
                .call(&ink_e2e::bob(), meta_tx_rollup_cond_eq, 0, None)
                .await;
            assert!(
                result.is_err(),
                "This message should not be proceed because the nonce is obsolete"
            );

            Ok(())
        }
    }
}

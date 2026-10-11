use super::*;

fn keymaker(pcr0: &str) -> Record {
    let mut value = record("https://alpha.example.com", Service::Keymaker);
    value.policy["sets"][0]["pcrs"]["0"] = pcr0.repeat(48).into();
    value
}

#[test]
fn first_verification_and_unchanged_measurements_preserve_policy() {
    let dir = tempfile::tempdir().unwrap();
    let client = client(dir.path(), "https://alpha.example.com");
    let path = record_path(&client, Service::Keymaker).unwrap();
    let first = keymaker("ab");
    first.policy_text().unwrap();
    save_record(&path, &first).unwrap();
    let previous = read_record(&client, Service::Keymaker).unwrap().unwrap();
    let mut next = keymaker("AB");
    next.retain_keymaker_history(&previous, 100).unwrap();
    assert_eq!(next.policy, first.policy);
}

#[test]
fn successive_upgrades_preserve_cutoffs_and_shared_history() {
    let first = keymaker("ab");
    let mut second = keymaker("cd");
    second.retain_keymaker_history(&first, 100).unwrap();
    let mut third = keymaker("ef");
    third.retain_keymaker_history(&second, 200).unwrap();
    let policy = third.parsed_policy().unwrap();
    assert_eq!(policy.sets.len(), 3);
    assert_eq!(policy.sets[0].pcrs[&0], vec![0xef; 48]);
    assert_eq!(policy.sets[0].expires_at_unix_seconds, None);
    assert_eq!(policy.sets[1].pcrs[&0], vec![0xcd; 48]);
    assert_eq!(policy.sets[1].expires_at_unix_seconds, Some(200));
    assert_eq!(policy.sets[2].pcrs[&0], vec![0xab; 48]);
    assert_eq!(policy.sets[2].expires_at_unix_seconds, Some(100));
    let mut repeated = keymaker("EF");
    repeated.retain_keymaker_history(&third, 300).unwrap();
    assert_eq!(repeated.policy, third.policy);

    let dir = tempfile::tempdir().unwrap();
    let client = client(dir.path(), "https://alpha.example.com");
    save_record(&record_path(&client, Service::Keymaker).unwrap(), &third).unwrap();
    // A fresh reader accepts the existing record format with historical sets.
    let loaded = read_record(&client, Service::Keymaker).unwrap().unwrap();
    assert_eq!(loaded.parsed_policy().unwrap(), policy);
}

#[test]
fn approving_a_retired_image_reactivates_it_without_duplicates() {
    let first = keymaker("ab");
    let mut second = keymaker("cd");
    second.retain_keymaker_history(&first, 100).unwrap();
    let mut third = keymaker("ef");
    third.retain_keymaker_history(&second, 200).unwrap();
    let mut rollback = keymaker("AB");
    rollback.retain_keymaker_history(&third, 300).unwrap();
    let policy = rollback.parsed_policy().unwrap();
    assert_eq!(policy.sets.len(), 3);
    assert_eq!(policy.sets[0].pcrs[&0], vec![0xab; 48]);
    assert_eq!(policy.sets[0].expires_at_unix_seconds, None);
    assert_eq!(policy.sets[1].pcrs[&0], vec![0xef; 48]);
    assert_eq!(policy.sets[1].expires_at_unix_seconds, Some(300));
    assert_eq!(policy.sets[2].expires_at_unix_seconds, Some(200));
}

#[test]
fn invalid_history_is_rejected_and_live_key_service_remains_single_set() {
    let mut next = keymaker("cd");
    next.retain_keymaker_history(&keymaker("ab"), 100).unwrap();
    let valid = next.policy.clone();
    // Two current sets.
    next.policy["sets"][1]["expires_at_unix_seconds"] = serde_json::Value::Null;
    assert!(next.policy_text().is_err());
    // No current set.
    next.policy = valid.clone();
    next.policy["sets"][0]["expires_at_unix_seconds"] = 200.into();
    assert!(next.policy_text().is_err());
    // Duplicate decoded measurements, despite differing hex case and cutoffs.
    next.policy = valid.clone();
    next.policy["sets"][1]["pcrs"] = next.policy["sets"][0]["pcrs"].clone();
    next.policy["sets"][1]["pcrs"]["0"] = "CD".repeat(48).into();
    assert!(next.policy_text().is_err());
    next.policy = valid.clone();
    next.policy["sets"][1]["pcrs"]["2"] = "00".repeat(48).into();
    assert!(next.policy_text().is_err());
    next.policy = valid.clone();
    next.policy["sets"][1]["expires_at_unix_seconds"] = "invalid".into();
    assert!(next.policy_text().is_err());
    next.policy = valid;
    next.service = Service::KeyService;
    assert!(next.policy_text().is_err());
    let old_live = record("https://alpha.example.com", Service::KeyService);
    let mut new_live = record("https://alpha.example.com", Service::KeyService);
    new_live.policy["sets"][0]["pcrs"]["0"] = "cd".repeat(48).into();
    let expected = new_live.policy.clone();
    new_live.retain_keymaker_history(&old_live, 200).unwrap();
    assert_eq!(new_live.policy, expected);
    new_live.policy_text().unwrap();
}

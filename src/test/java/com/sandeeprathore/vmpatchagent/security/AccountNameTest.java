package com.sandeeprathore.vmpatchagent.security;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AccountNameTest {

	@Test
	void splitsDomainBackslashUser() {
		assertThat(AccountName.parse("CORP\\alice")).isEqualTo(new AccountName("alice", "CORP"));
	}

	@Test
	void passesAUpnWithoutADomain() {
		assertThat(AccountName.parse("alice@corp.example")).isEqualTo(new AccountName("alice@corp.example", null));
	}

	@Test
	void treatsABareNameAsLocal() {
		assertThat(AccountName.parse(" alice ")).isEqualTo(new AccountName("alice", "."));
	}

}

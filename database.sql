CREATE TABLE dns_records (
	id bigint unsigned auto_increment primary key,
	domain varchar(255) not null,
	type varchar(10) not null,
	value varchar(255)
);

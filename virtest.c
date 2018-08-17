#include <err.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libvirt/libvirt.h>
#include <libvirt/libvirt-storage.h>
#include <libvirt/virterror.h>

static float ktog(float kb)
{
	return kb / 1024.0 / 1024.0;
}

static int creds[] = {
	VIR_CRED_AUTHNAME, // esx expects AUTHNAME
	VIR_CRED_PASSPHRASE,
	VIR_CRED_USERNAME,
};

static struct cred {
	char *username;
	char *passwd;
} virt_cred;

static int authCb(virConnectCredentialPtr cred, unsigned int ncred,
			void *cbdata)
{
	struct cred *vcred = (struct cred *)cbdata;
	size_t i;

	for (i = 0; i < ncred; i++) {
		switch (cred[i].type) {
		case VIR_CRED_USERNAME:
		case VIR_CRED_AUTHNAME: {
			size_t len = strlen(vcred->username);
			if (len == 0) {
				printf("invalid user\n");
				return -1;
			}

			cred[i].result = strdup(vcred->username);
			cred[i].resultlen = len;
			break;
		}
		case VIR_CRED_PASSPHRASE: {
			size_t len = strlen(vcred->passwd);
			if (len == 0) {
				printf("invalid pass\n");
				return -1;
			}

			cred[i].result = strdup(vcred->passwd);
			cred[i].resultlen = len;
			break;
		}
		default:
			printf("Cred type not found: %d\n", cred[i].type);
		}
	}

	return 0;
}

static int dom_info(virConnectPtr conn, char *dom_name)
{
	virDomainPtr dom;
	virDomainInfo dinfo;
	char *os_dom, *xmldesc;
	int autostart;

	dom = virDomainLookupByName(conn, dom_name);
	if (!dom) {
		fprintf(stderr, "Domain %s not found\n", dom_name);
		return -1;
	}

	if (virDomainGetInfo(dom, &dinfo) < 0) {
		fprintf(stderr, "Could not get info: %s\n",
				virGetLastErrorMessage());
		return -1;
	}

	printf("Domain %s Info:\n", dom_name);
	printf("\tMax vCPUs: %d\n", virDomainGetMaxVcpus(dom));
	printf("\tIs running: %s\n", dinfo.state == VIR_DOMAIN_RUNNING
			? "yes" : "no");
	printf("\tMax Memory Allowed: %.2fG\n", ktog(dinfo.maxMem));
	printf("\tUsed memory: %.2fG\n", ktog(dinfo.memory));
	printf("\tNumber of virtual CPUs: %d\n", dinfo.nrVirtCpu);
	printf("\tCPU time (nanoseconds): %lld\n", dinfo.cpuTime);

	if (virDomainGetAutostart(dom, &autostart) != -1)
		printf("\tAutostart: %s\n", autostart ? "yes" : "no");

	os_dom = virDomainGetOSType(dom);
	if (os_dom) {
		printf("\tOS type: %s\n", os_dom);
		free(os_dom);
	}

	xmldesc = virDomainGetXMLDesc(dom, 0);
	if (xmldesc) {
		printf("Domain XML Description:\n%s\n", xmldesc);
		free(xmldesc);
	}

	return 0;
}

static void storage(virConnectPtr conn)
{
	int i, ret, nstorage;

	nstorage = virConnectNumOfStoragePools(conn);
	printf("Number of Storage Pools: %d\n", nstorage);
	if (nstorage > 0) {
		char **npools = (char **)malloc(sizeof(char **) * nstorage);

		if (virConnectListStoragePools(conn, npools, nstorage) == nstorage) {
			printf("Storage pools by name:\n");
			for (i = 0; i < nstorage; i++) {
				printf("\t%s\n", npools[i]);
				free(npools[i]);
			}
		}

		free(npools);

		virStoragePoolPtr *pools;
		ret = virConnectListAllStoragePools(conn, &pools, nstorage);
		if (ret > 1) {
			printf("Storage names:\n");
			for (i = 0; i < ret; i++) {
				printf("\t%s\n", virStoragePoolGetName(pools[i]));
				virStoragePoolFree(pools[i]);
			}
		}
	}
}

static void networks(virConnectPtr conn)
{
	int i, nets;

	nets = virConnectNumOfNetworks(conn);
	printf("Networks: %d\n", nets);

	if (nets > 0) {
		char **net_list = (char **)malloc(sizeof(char **) * nets);

		if (virConnectListNetworks(conn, net_list, nets) == nets) {
			printf("Networks by name:\n");
			for (i = 0; i < nets; i++) {
				printf("\t%s\n", net_list[i]);
				free(net_list[i]);
			}
		}

		free(net_list);
	}
}

int main(int argc, char **argv)
{
	virConnectAuth cauth = {0};
	virConnectPtr conn;
	virNodeInfo ninfo;
	virSecurityModel secmod;
	virDomainPtr *domList;
	char *caps, *uri, *hostname;
	unsigned long ver, libver;
	ssize_t i;
	int numNames, ret = 0;

	if (argc < 3)
		errx(EXIT_FAILURE, "Usage: libvirt <user> <passwd> <uri>");

	virt_cred.username = argv[1];
	virt_cred.passwd = argv[2];

	cauth.credtype = creds;
	cauth.ncredtype = sizeof(creds)/sizeof(int);
	cauth.cb = authCb;
	cauth.cbdata = &virt_cred;

	conn = virConnectOpenAuth(argv[3], &cauth, 0);
	if (conn == NULL)
		errx(EXIT_FAILURE, "Failed to connect to hypervisor");

	caps = virConnectGetCapabilities(conn);
	printf("Capabilities: %s\n", caps);
	free(caps);

	uri = virConnectGetURI(conn);
	printf("Connected at %s\n", uri);
	free(uri);

	hostname = virConnectGetHostname(conn);
	printf("Hostname: %s\n", hostname);
	free(hostname);

	virConnectGetVersion(conn, &ver);
	virConnectGetLibVersion(conn, &libver);

	printf("Virtualizaton Type: %s\n", virConnectGetType(conn));
	printf("Driver Version: %lu\n", ver);
	printf("LibVirt Version: %lu\n", libver);
	ret = virConnectGetMaxVcpus(conn, NULL);
	if (ret != -1)
		printf("Max vCPUS: %d\n", ret);
	printf("Node Free Memory: %.2fG\n", ktog(virNodeGetFreeMemory(conn)) / 1024.0);

	printf("Connention is encrypted: %d\n", virConnectIsEncrypted(conn));
	printf("Connention is secure: %d\n", virConnectIsSecure(conn));

	storage(conn);
	networks(conn);

	virNodeGetInfo(conn, &ninfo);

	printf("Node Info:\n");
	printf("\tModel: %s\n", ninfo.model);
	printf("\tMemory: %.2fG\n", ktog(ninfo.memory));
	printf("\tCPUs: %d\n", ninfo.cpus);

	if (virNodeGetSecurityModel(conn, &secmod) != -1) {
		printf("\tSecurity Model: %s\n", secmod.model);
		printf("\tSecurity DOI: %s\n", secmod.doi);
	}

	printf("\tActive Domains: %d\n",
			virConnectNumOfDomains(conn));
	printf("\tInactive Domains: %d\n",
			virConnectNumOfDefinedDomains(conn));

	numNames = virConnectListAllDomains(conn, &domList,
			VIR_CONNECT_LIST_DOMAINS_ACTIVE |
			VIR_CONNECT_LIST_DOMAINS_INACTIVE);
	if (numNames == -1) {
		printf("Failed to get All domains: %s\n",
				virGetLastErrorMessage());
		goto out;
	}

	if (numNames > 0) {
		printf("Domains:\n");
		for (i = 0; i < numNames; i++) {
			printf("\t%8s: %s\n", virDomainGetName(domList[i])
				, (virDomainIsActive(domList[i]) == 1)
					? "Active" : "Non-active");
			virDomainFree(domList[i]);
		}
	}

	free(domList);

	if (argc == 5)
		ret = dom_info(conn, argv[4]);

out:
	virConnectClose(conn);

	return ret;
}

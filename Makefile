.PHONY: clean generate-plans test

clean:
	@echo "Cleaning up Terraform files"
	@for service in $(SERVICES); do \
		cd $$service; \
		rm -rf .terraform* tfplan.bin terraform.tfstate; \
		cd -; \
	done

generate-plans: clean
	@localstack stop || true
	@localstack start -d
	@for service in $$(find testdata -mindepth 1 -maxdepth 1 -type d); do \
		echo "Generating $$service Terraform Plan"; \
		cd $$service; \
		terraform init; \
		terraform plan --out=tfplan.bin; \
		terraform show -json tfplan.bin > tfplan.json; \
		rm -rf .terraform* tfplan.bin terraform.tfstate; \
		cd -; \
	done
	@localstack stop

test:
	go test -v ./...
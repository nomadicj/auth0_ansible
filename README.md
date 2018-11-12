### To run the ansible module locally

- Install python 3.6
- Create a folder named 'local' under group-vars and add main.yml similar to other env and point to 'localhost'
- Create 'local.yml' under inventory folder with host as 'localhost'
- Run ``pip3 install auth0-python hvac deepdiff tenacity``
- Run ``ansible-playbook auth0.yml -vvv -i inventory/local.yml`` from infra/ansible
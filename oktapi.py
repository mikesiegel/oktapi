from okta import UsersClient
from okta import FactorsClient
import requests
import pprintz
import concurrent.futures
from datetime import datetime, timezone, timedelta
import dateutil
import time
import configparser
import click
import sys

MAX_THREADS = 5

class User():
  def __init__(self):
    expires = None
    username = None
    poll_url = None
    result = None
    sent_time = None
  
def poll_factor(poll_url, expires, username, API_KEY):
  header = { "Authorization": "SSWS {}".format(API_KEY) }
  print("Polling {}".format(username))
  waiting = True
  while(datetime.now(timezone.utc) < (dateutil.parser.parse(expires) + timedelta(8)) and waiting):
   # print("Polling {} {}".format(datetime.now(timezone.utc), expires))
    r = requests.get(poll_url, headers=header)
    #pprint.pprint(r.json())
    if(r.json()['factorResult'] != 'WAITING'):
      waiting = False
    time.sleep(5)
  print("Received response for {} status: {}".format(username, r.json()['factorResult']))
  return r.json()['factorResult'], username, datetime.now(timezone.utc)

def poll_factor_executor(users, API_KEY, threads):
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        fs = [executor.submit(poll_factor, user.poll_url, user.expires, user.username, API_KEY)
                               for user in users]
        for future in concurrent.futures.as_completed(fs):
           result, username, response_time = future.result()
           results['{}'.format(username)] = [ result, response_time ]

    return results

def verify_factor(userid, factorid, API_KEY, URL):
  # Okta SDK bug workaround
  header = { "Authorization": "SSWS {}".format(API_KEY) }
  url = '{}/api/v1/users/{}/factors/{}/verify'.format(URL, userid, factorid)
  #print("Url is {}".format(url))
  r = requests.post(url, headers=header)
  return r

def parse_factor_response(response):
  poll_url = response['_links']['poll']['href']
  expires = response['expiresAt']
  return poll_url, expires

def parse_config():
  config = configparser.ConfigParser()
  config.read("oktapi.cfg")
  return config['oktapi']['apikey'], config['oktapi']['url']

def read_accounts(filename):
  account_list = []
  try:
    with open(filename, 'r') as account_file:
      for line in account_file:
        account_list.append(line.rstrip())
  except Exception as e:
    print("Can't read input file")
    sys.exit(1)

  return account_list

def write_output(output, filename):
  try:
    with open(filename, 'w') as output_file:
      output_file.write("account,result,time\n")
      for key, value in output.items():
        output_file.write("{},{},{}\n".format(key, value[0], value[1],))
  except Exception as e:
    print("Can't write output filei {}".format(e))
    sys.exit(1)

@click.command()
@click.option('--threads', default=5, help='Max threads')
@click.option('--filename', help='List of account addresses to read')
@click.option('--output', help='CSV file to write')
def main(filename, output, threads=5):
  error_dict = {}

  API_KEY, URL = parse_config()

  try:
    usersClient = UsersClient(URL, API_KEY)
    factorClient = FactorsClient(URL, API_KEY)
  except Exception as e:
    print("Unable to authenticate to Okta API, exiting.")
    return

  accounts =  read_accounts(filename)
 
  users = []

  for account in accounts:
    # probably need a rate limit or multi threading here
    user = None
    poll_url = None
    expires = None
    factor = None
    
    try:
      user = usersClient.get_user(account)
      factors = factorClient.get_lifecycle_factors(user.id)
    except Exception as e:
      print("Error raised, user {} probably doesnt exist ".format(account))
      error_dict['{}'.format(account)] = [ 'ERROR', datetime.now(timezone.utc) ] 

    has_push = False

    for factor in factors:
      if user is None:
        continue
      if(factor.factorType == 'push'):
        has_push = True
        # this doesnt work :( issue 66
        factor_response = verify_factor(user.id, factor.id, API_KEY, URL)
        #pprint.pprint(factor_response.json())
        poll_url, expires = parse_factor_response(factor_response.json())
        u = User()
       
        u.poll_url = poll_url
        u.expires = expires
        u.username = account
        users.append(u)
     
    if not has_push and not user is None:
      error_dict['{}'.format(account)] = [ 'NOPUSH', datetime.now(timezone.utc) ]

  results = poll_factor_executor(users, API_KEY, threads)
  # only works in Python 3.5 and greater
  results = { **error_dict, **results }
  pprint.pprint(results)
  write_output(results, output)

if __name__ == '__main__':
    main()





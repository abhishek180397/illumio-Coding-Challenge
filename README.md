# illumio-Coding-Challenge
Coding Challenge 
I thought about how to make the function work quickly, because the naive solution is just to check all the rules one by one, but I knew that to save on time complexity, I wanted to pre-calculate as much as I could inside the constructor function. I realized that I could break down the initial csv into 4 categories inbound and outbounf with tcp and udp .

I used the internet as in how to take the input as a csv file and it directed me to a pandas library.so I created a pandas dataframe for direction and protocol. I also decided that I wanted to convert all rules's port and ip_address values to ranges in order to simplify the number of cases I have to deal with.

Once I created the panda framework it was pretty simple I used my helper functions to reduce the iterations and I think it can be done in a much more efficient way by merging the overlapping rules.


Team:
I would like to work in the date team or policy team. I think I can add an impact in these teams

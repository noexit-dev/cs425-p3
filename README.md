# Project 3: Subnetting and Forwarding

- Name: Rylee Hilde
- Email: ryleehilde@u.boisestate.edu
- Class: CS425-001

## Known Bugs or Issues

There are no known bugs or issues in this project

## Experience

My experience went quite smooth. I liked having the guidance on what functions I needed to implement and what the output should look like. Also being highlighted on the test suite was also very helpful on what I needed to test and lookout for.

## Design

A /0 covers every IPv4 address. The mask function returns zero directly to avoid shifting a 32-bit value by 32, which is undefined in C. Its network address is 0.0.0.0 and its broadcast address is 255.255.255.255. The usable host range is 0.0.0.1 through 255.255.255.254, giving 4,294,967,294 hosts. The host count calculation uses 64-bit arithmetic so the intermediate value of 2^32 fits.

A /31 represents a point-to-point link, so both addresses are usable hosts. The first and last host functions return the lowest and highest addresses without reserving either as a network or broadcast address, and the host count is two. A /32 represents one host, so its network, broadcast, first host, and last host calculations all return the same address, and its host count is one.

The forwarding table stores routes in a growable array. To find the longest prefix, the lookup scans every route and checks whether the destination address ANDed with the route's subnet mask equals the route's network address. It keeps the matching route with the largest prefix length, so the result does not depend on insertion order. For example, 10.1.2.200 matches the example table's /8, /16, /24, and /25 routes, but the /25 wins because it is the most specific. The default /0 route matches everything and is selected only when no more specific route matches. If no route matches, the lookup returns NULL and the command prints unreachable. Each lookup takes O(n) time for n routes.
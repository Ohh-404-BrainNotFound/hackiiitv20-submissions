import React, { Component } from 'react';
import './style.css';
import { NavLink } from 'react-router-dom';
class index extends Component {
  render() {
    return (
      <div>
        <div className="mid__section">
          <div className="content">
            <h1 className="head">
              some random lines i do not know what to include but sill we will
              include some reandon lines in it for surw
            </h1>
            <h1 className="sub__head">
              some random lines i do not know what to include but sill{' '}
            </h1>
          </div>
          <div className="img__holder">
            <img className="lady__img" src="./Images/lady.png"></img>
          </div>
        </div>
      </div>
    );
  }
}

export default index;

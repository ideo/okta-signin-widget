/*!
 * Copyright (c) 2015-2016, Okta, Inc. and/or its affiliates. All rights reserved.
 * The Okta software accompanied by this notice is provided pursuant to the Apache License, Version 2.0 (the "License.")
 *
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 */

define([
  'okta',
  'okta/jquery',
  'util/FormController',
  'util/Enums',
  'util/FormType',
  'util/ValidationUtil',
  'vendor/lib/q',
  'views/shared/ContactSupport',
  'views/shared/TextBox'
],
function (Okta, $, FormController, Enums, FormType, ValidationUtil, Q, ContactSupport, TextBox) {

  var _ = Okta._;
  var Footer = Okta.View.extend({
    template: '\
      <a href="#" class="link help js-back" data-se="back-link">\
        {{i18n code="goback" bundle="login"}}\
      </a>\
      {{#if helpSupportNumber}}\
      <a href="#" class="link goto js-contact-support">\
        {{i18n code="mfa.noAccessToEmail" bundle="login"}}\
      </a>\
      {{/if}}\
    ',
    className: 'auth-footer',
    events: {
      'click .js-back' : function (e) {
        e.preventDefault();
        this.back();
      },
      'click .js-contact-support': function (e) {
        e.preventDefault();
        this.state.trigger('contactSupport');
        this.$('.js-contact-support').hide();
      }
    },
    getTemplateData: function () {
      return this.settings.pick('helpSupportNumber');
    },
    back: function () {
      this.state.set('navigateDir', Enums.DIRECTION_BACK);
      this.options.appState.trigger('navigate', '');
    }
  });

  return FormController.extend({
    className: 'register',
    Model: {
      props: {
        firstname: ['string', true],
        lastname: ['string', true],
        username: ['string', true],
        password: ['string', true]
      },
      validate: function () {
        var invalid = ValidationUtil.validateUsername(this);
        invalid = invalid || ValidationUtil.validateRequired(this, 'firstname');
        invalid = invalid || ValidationUtil.validateRequired(this, 'lastname');
        invalid = invalid || ValidationUtil.validateRequired(this, 'username');
        invalid = invalid || ValidationUtil.validateRequired(this, 'password');
        invalid = invalid || ValidationUtil.validatePasswordStrength(this);

        return invalid;
      },
      save: function () {
        var self = this;
        return this.startTransaction(function (authClient) {
          var deferred = Q.defer();
          $.post('/api/v1/users', {
            first_name: self.get('firstname'), // eslint-disable-line camelcase
            last_name: self.get('lastname'), // eslint-disable-line camelcase
            email: self.get('username'),
            password: self.get('password')
          }).done(function() {
            deferred.resolve(
              authClient.signIn({
                username: self.get('username'),
                password: self.get('password')
              })
            );
          }).fail(function(err) {
            if (err.responseJSON && err.responseJSON.data && err.responseJSON.data.error === 'DUPLICATE_EMAIL') {
              self.trigger('invalid', self, {
                'username': Okta.loc('registration.error.userName.notUniqueWithinOrg', 'login')
              });
            } else {
              self.trigger('invalid', self, {
                'username': Okta.loc('oform.error.unexpected', 'login')
              });
            }
          });

          return deferred.promise;
        })
        .fail(function () {
          //need empty fail handler on model to display errors on form
        });
        // this.startTransaction(function(authClient) {
        //   return authClient.forgotPassword({
        //     username: self.settings.transformUsername(self.get('username'), Enums.FORGOT_PASSWORD),
        //     factorType: self.get('factorType')
        //   });
        // })
        // .fail(function () {
        //   //need empty fail handler on model to display errors on form
        // });
      }
    },
    Form: {
      noCancelButton: true,
      save: _.partial(Okta.loc, 'registration.form.submit', 'login'),
      saveId: 'okta-registration-submit',
      title: _.partial(Okta.loc, 'registration.form.title', 'login'),
      formChildren: function () {
        /*eslint complexity: [2, 9] max-statements: [2, 23] */
        var formChildren = [];

        formChildren.push(FormType.Input({
          placeholder: Okta.loc('primaryauth.firstname.placeholder', 'login'),
          name: 'firstname',
          input: TextBox,
          type: 'text',
          params: {
            innerTooltip: Okta.loc('primaryauth.firstname.tooltip', 'login'),
            icon: 'person-16-gray'
          }
        }));

        formChildren.push(FormType.Input({
          placeholder: Okta.loc('primaryauth.lastname.placeholder', 'login'),
          name: 'lastname',
          input: TextBox,
          type: 'text',
          params: {
            innerTooltip: Okta.loc('primaryauth.lastname.tooltip', 'login'),
            icon: 'person-16-gray'
          }
        }));

        formChildren.push(FormType.Input({
          placeholder: Okta.loc('primaryauth.username.placeholder', 'login'),
          name: 'username',
          input: TextBox,
          type: 'text',
          params: {
            innerTooltip: Okta.loc('primaryauth.username.tooltip', 'login'),
            icon: 'person-16-gray'
          }
        }));

        formChildren.push(FormType.Input({
          placeholder: Okta.loc('primaryauth.password.placeholder', 'login'),
          name: 'password',
          input: TextBox,
          type: 'password',
          params: {
            innerTooltip: Okta.loc('primaryauth.password.tooltip', 'login'),
            icon: 'remote-lock-16'
          }
        }));

        formChildren.push(FormType.View({
          View: Okta.View.extend({
            className: 'consent-title',
            template: '\
              <p> \
                {{{i18n code="registration.agreeTerms" bundle="login" }}} \
                <a href="https://www.ideo.com" class="link" target="_blank"> \
                  {{{i18n code="consent.required.termsOfService" bundle="login" }}} \
                </a>. \
              </p>'
          })
        }));

        return formChildren;
      },
      initialize: function () {
        this.listenTo(this.state, 'contactSupport', function () {
          this.add(ContactSupport, '.o-form-error-container');
        });

        this.listenTo(this, 'save', function () {
          this.options.appState.set('username', this.model.get('username'));
          this.model.save();
        });
      },
      setDefaultFactorType: function (factorType) {
        if (_.isEmpty(this.model.get('factorType'))) {
          this.model.set('factorType', factorType);
        }
      },
      createRecoveryFactorButton: function (className, labelCode, factorType, form) {
        return FormType.Button({
          attributes: { 'data-se': className},
          className: 'button button-primary button-wide ' + className,
          title: Okta.loc(labelCode, 'login'),
          click: function () {
            form.clearErrors();
            if (this.model.isValid()) {
              this.model.set('factorType', factorType);
              form.trigger('save', this.model);
            }
          }
        });
      }
    },
    Footer: Footer,

    initialize: function () {
      this.options.appState.unset('username');
    }
  });

});

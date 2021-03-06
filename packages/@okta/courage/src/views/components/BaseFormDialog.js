define([
  'okta/jquery',
  'okta/underscore',
  'shared/views/BaseView',
  'shared/views/components/BaseModalDialog',
  'shared/views/forms/BaseForm'
],
function ($, _, BaseView, BaseModalDialog, BaseForm) {

  var FORM_FIELDS = [
    'save',
    'noCancelButton',
    'inputs',
    'subtitle',
    'autoSave',
    'focus',
    'cancel',
    'danger',
    'hasSavingState',
    'customSavingState',
    'parseErrorMessage'
  ];
  var FORM_DEFAULTS = {
    layout: 'o-form-wrap',
    scrollOnError: false
  };

  // jquery.simplemodoal options
  var SIMPLE_MODAL_PARAMS = {
    minWidth: 600,
    maxWidth: 950,
    focus: false,
    close: false,
    autoResize: false, // (use the resizeModal method, so that the scrolling goes to content, not the whole modal)
    autoPosition: true
  };

  /**
   * @class Okta.FormDialog
   *
   * Okta.FormDialog is a facade layer for a form that lives in a modal dialog.
   *
   * The API is proxying the {@link Okta.Form} API for the most parts.
   * It also triggers all the form events
   * It takes care of repositioning, resizing, closing the dialog on cancel, and so on.
   *
   * ```javascript
   * var AddUserDialog = Okta.FormDialog({
   *   autoSave: true,
   *   title: 'Add a User',
   *   inputs: [
   *     {
   *       type: 'text',
   *       name: 'fname',
   *       label: 'First Name'
   *     },
   *     {
   *       type: 'text',
   *       name: 'lname',
   *       label: 'Last Name'
   *     }
   *   ]
   * });
   * var dialog = new AddUserDialog({model: new MyModel()}).render(); // renders the modal dialog on the page
   * this.listenTo(dialog, 'saved', function (model) {
   *   // the model is now saved
   * });
   * ```
   * @extends Okta.View
   */

   /**
    * @event save
    * @inheritdoc Okta.Form#event-save
    */
    /**
    * @event saved
    * @inheritdoc Okta.Form#event-saved
    */
    /**
    * @event resize
    * @inheritdoc Okta.Form#event-resize
    */
    /**
    * @event cancel
    * @inheritdoc Okta.Form#event-cancel
    */

  return BaseView.extend({

    /**
     * @constructor
     */
    constructor: function (options) {
      /* eslint max-statements: [2, 13] */

      var Form = BaseForm.extend(_.extend({}, FORM_DEFAULTS, _.pick(this, FORM_FIELDS)));
      this.form = new Form(_.omit(options, 'title', 'subtitle'));

      this.listenTo(this.form, 'resize', _.debounce(_.bind(this.resizeModal, this), 100));

      // trigger all form events
      var removeFn = _.bind(this.remove, this);
      this.listenTo(this.form, 'all', function () {
        this.trigger.apply(this, arguments);
        if (arguments[0] === 'cancel') {
          removeFn();
        }
      });

      $(window).resize(_.debounce(_.bind(this.resizeModal, this), 100));

      var Dialog = BaseModalDialog.extend({
        title: this.title,
        className: this.className,
        params: _.extend({}, SIMPLE_MODAL_PARAMS, this.params)
      });

      this.dialog = new Dialog(options);
      this.dialog.add(this.form);
      this.el = this.dialog.el;


      BaseView.apply(this, arguments);

      if (this.form.getAttribute('autoSave')) {
        this.listenTo(this, 'saved', this.remove);
      }

    },

    /**
     * @property title
     * @inheritdoc Okta.Form#title
     */
    /**
     * @property subtitle
     * @inheritdoc Okta.Form#subtitle
     */
    /**
     * @property save
     * @inheritdoc Okta.Form#save
     */
    /**
     * @property inputs
     * @inheritdoc Okta.Form#inputs
     */
    /**
     * @property noCancelButton
     * @inheritdoc Okta.Form#noCancelButton
     */
    /**
     * @property autoSave
     * @inheritdoc Okta.Form#autoSave
     */
    /**
     * @property [params={minWidth: 600, maxWidth: 950, focus: false, close: false}]
     * @inheritdoc Okta.ModalDialog#params
     */

    /**
     * The form instance generated by the constructor.
     * Should **not** be referenced locally, exposed externally for test purposes.
     * @type {Okta.Form}
     * @private
     * @readonly
     */
    form: undefined,

    /**
     * The dialog instance generated by the constructor.
     * Should **not** be referenced locally, exposed externally for test purposes.
     * @type {Okta.ModalDialog}
     * @private
     * @readonly
     */
    dialog: undefined,

    /**
     * @alias Okta.Form#addInput
     */
    addInput: function () {
      return this.form.addInput.apply(this.form, arguments);
    },

    /**
     * @alias Okta.Form#addButton
     */
    addButton: function () {
      return this.form.addButton.apply(this.form, arguments);
    },

    /**
     * @alias Okta.Form#addDivider
     */
    addDivider: function () {
      return this.form.addDivider.apply(this.form, arguments);
    },

    /**
     * @alias Okta.Form#addSectionTitle
     */
    addSectionTitle: function () {
      return this.form.addSectionTitle.apply(this.form, arguments);
    },

    /**
     * @alias Okta.View#add
     */
    add: function () {
      return this.form.add.apply(this.form, arguments);
    },

    /**
     * @alias Okta.View#render
     */
    render: function () {
      this.preRender();
      this.dialog.render.apply(this.dialog, arguments);
      _.defer(_.bind(this.resizeModal, this));
      this.postRender();
      return this;
    },

    /**
     * @alias Okta.View#remove
     */
    remove: function () {
      this.dialog.remove.apply(this.dialog, arguments);
      return BaseView.prototype.remove.apply(this, arguments);
    },

    /**
     * Resize modal to fit window height
     * the whole modal will be within the viewport, only the form content is scrollable
     * there's no good solution to totally fix the width issue yet for tiny window,
     * leave it for jquery simplemodal autoResize to do its best
     */
    resizeModal: function () {
      var modal = $('.simplemodal-container-new'),
          form = this.form,
          modalHeight = modal.height(),
          modalMinHeight = _.isNumber(this.dialog.params.minHeight) ? this.dialog.params.minHeight : 0,
          windowHeight = $(window).height();
      if (modalMinHeight <= modalHeight) {
        if (modalHeight >= windowHeight) {
          form.contentHeight(
            windowHeight - this.dialog.$('h2').outerHeight() - form.$('.o-form-button-bar').outerHeight() -
            (modal.outerHeight(true) - form.$el.outerHeight(true)));
        }
        else {
          form.contentHeight(
            form.contentHeight() + (windowHeight - modalHeight) - (modal.outerHeight() - modalHeight)
          );
        }
        this.dialog.resize.apply(this.dialog, arguments);
      }
    },

    /**
     * @alias Okta.Form#clearErrors
     */
    clearErrors: function () {
      return this.form.clearErrors.apply(this.form, arguments);
    }

  });

});
